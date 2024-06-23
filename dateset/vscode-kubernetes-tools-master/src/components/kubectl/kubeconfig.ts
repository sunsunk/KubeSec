import * as vscode from 'vscode';
import { fs } from '../../fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as shelljs from 'shelljs';
import { refreshExplorer } from '../clusterprovider/common/explorer';
import { getActiveKubeconfig, getUseWsl } from '../config/config';
import * as kubernetes from '@kubernetes/client-node';
import { mkdirpAsync } from '../../utils/mkdirp';

interface Named {
    readonly name: string;
}

export interface HostKubeconfigPath {
    readonly pathType: 'host';
    readonly hostPath: string;
}

export interface WSLKubeconfigPath {
    readonly pathType: 'wsl';
    readonly wslPath: string;
}

export type KubeconfigPath = HostKubeconfigPath | WSLKubeconfigPath;

export async function loadKubeconfig(): Promise<kubernetes.KubeConfig> {
    const kubeconfig = new kubernetes.KubeConfig();
    const kubeconfigPath = getKubeconfigPath();

    if (kubeconfigPath.pathType === 'host') {
        kubeconfig.loadFromFile(kubeconfigPath.hostPath);
    } else if (kubeconfigPath.pathType === 'wsl') {
        const result = shelljs.exec(`wsl.exe sh -c "cat ${kubeconfigPath.wslPath}"`, { silent: true }) as shelljs.ExecOutputReturnValue;
        if (!result) {
            throw new Error(`Impossible to retrieve the kubeconfig content from WSL at path '${kubeconfigPath.wslPath}'. No result from the shelljs.exe call.`);
        }

        if (result.code !== 0) {
            throw new Error(`Impossible to retrieve the kubeconfig content from WSL at path '${kubeconfigPath.wslPath}. Error code: ${result.code}. Error output: ${result.stderr.trim()}`);
        }

        kubeconfig.loadFromString(result.stdout.trim());
    } else {
        throw new Error(`Kubeconfig path type is not recognized.`);
    }

    return kubeconfig;
}

export function getKubeconfigPath(): KubeconfigPath {
    // If the user specified a kubeconfig path -WSL or not-, let's use it.
    let kubeconfigPath: string | undefined = getActiveKubeconfig();

    if (getUseWsl()) {
        if (!kubeconfigPath) {
            // User is using WSL: we want to use the same default that kubectl uses on Linux ($KUBECONFIG or home directory).
            const result = shelljs.exec('wsl.exe sh -c "${KUBECONFIG:-$HOME/.kube/config}"', { silent: true }) as shelljs.ExecOutputReturnValue;
            if (!result) {
                throw new Error(`Impossible to retrieve the kubeconfig path from WSL. No result from the shelljs.exe call.`);
            }

            if (result.code !== 0) {
                throw new Error(`Impossible to retrieve the kubeconfig path from WSL. Error code: ${result.code}. Error output: ${result.stderr.trim()}`);
            }
            kubeconfigPath = result.stdout.trim();
        }
        return {
            pathType: 'wsl',
            wslPath: kubeconfigPath
        };
    }

    if (!kubeconfigPath) {
        kubeconfigPath = process.env['KUBECONFIG'];
    }
    if (!kubeconfigPath) {
        // Fall back on the default kubeconfig value.
        kubeconfigPath = path.join((process.env['HOME'] || process.env['USERPROFILE'] || '.'), ".kube", "config");
    }
    return {
        pathType: 'host',
        hostPath: kubeconfigPath
    };
}

export async function mergeToKubeconfig(newConfigText: string): Promise<void> {
    const kubeconfigPath = getKubeconfigPath();

    if (kubeconfigPath.pathType === 'wsl') {
        vscode.window.showErrorMessage("You are on Windows, but are using WSL-based tools. We can't merge into your WSL kubeconfig. Consider running VS Code in WSL using the Remote Extensions.");
        return;
    }

    const kcfile = kubeconfigPath.hostPath;
    const kcfileExists = await fs.existsAsync(kcfile);

    const kubeconfigText = kcfileExists ? await fs.readTextFile(kcfile) : '';
    const kubeconfig = yaml.safeLoad(kubeconfigText) || {};
    const newConfig = yaml.safeLoad(newConfigText);

    for (const section of ['clusters', 'contexts', 'users']) {
        const existing: Named[] | undefined = kubeconfig[section];
        const toMerge: Named[] | undefined = newConfig[section];
        if (!toMerge) {
            continue;
        }
        if (!existing) {
            kubeconfig[section] = toMerge;
            continue;
        }
        await mergeInto(existing, toMerge);
    }

    if (!kcfileExists && newConfig.contexts && newConfig.contexts[0]) {
        kubeconfig['current-context'] = newConfig.contexts[0].name;
    }

    const merged = yaml.safeDump(kubeconfig, { lineWidth: 1000000, noArrayIndent: true });

    if (kcfileExists) {
        const backupFile = kcfile + '.vscode-k8s-tools-backup';
        if (await fs.existsAsync(backupFile)) {
            await fs.unlinkAsync(backupFile);
        }
        await fs.renameAsync(kcfile, backupFile);
    } else {
        await mkdirpAsync(path.dirname(kcfile));
    }
    await fs.writeTextFile(kcfile, merged);

    await refreshExplorer();
    await vscode.window.showInformationMessage(`New configuration merged to ${kcfile}`);
}

async function mergeInto(existing: Named[], toMerge: Named[]): Promise<void> {
    for (const toMergeEntry of toMerge) {
        if (existing.some((e) => e.name === toMergeEntry.name)) {
            // we have CONFLICT and CONFLICT BUILDS CHARACTER
            await vscode.window.showWarningMessage(`${toMergeEntry.name} already exists - skipping`);
            continue;  // TODO: build character
        }
        existing.push(toMergeEntry);
    }
}
