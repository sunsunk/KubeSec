import * as vscode from 'vscode';
import { LocalTunnelDebugProvider } from './localtunneldebugprovider.extension';
import { getLocalTunnelDebugProvider } from '../config/config';

export class LocalTunnelDebugger {
    private readonly providers = Array.of<LocalTunnelDebugProvider>();

    register(provider: LocalTunnelDebugProvider) {
        console.log(`Registered local tunnel debugger type ${provider.id}`);
        this.providers.push(provider);
    }

    startLocalTunnelDebugSession(target?: any) {
        const providerSetting: string | undefined = getLocalTunnelDebugProvider();
        const providerName: string | undefined = providerSetting ? providerSetting : this.providers.map((p) => p.id).sort()[0];
        const providerToUse: LocalTunnelDebugProvider | undefined = this.providers.find((p) => p.id === providerName);

        // On success start early.
        if (providerToUse) {
            providerToUse.startLocalTunnelDebugging(target);
            return;
        }

        // Handle failure scenarios.
        let message = "";
        if (providerName) {
            message = `You have configured VSCode to use Local Tunnel debugger '${providerName}', but it is not installed.`;
        }
        else if (!this.providers.length) {
            message = 'You do not have a Local Tunnel Debug Provider installed.';
        }

        LocalTunnelDebugger.promptToFindOnMarketplace(message);
    };

    static promptToFindOnMarketplace(message: string) {
        const browseExtensions = "Find Providers on Marketplace";

        vscode.window.showInformationMessage(message, browseExtensions)
            .then((selection: string | undefined) => {
                if (selection === browseExtensions) {
                    vscode.commands.executeCommand('extension.vsKubernetesFindLocalTunnelDebugProviders');
                }
            });
    }
}


