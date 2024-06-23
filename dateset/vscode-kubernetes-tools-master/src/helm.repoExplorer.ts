import * as vscode from 'vscode';
import * as _ from 'lodash';

import { Host } from './host';
import * as helm from './helm.exec';
import { HELM_OUTPUT_COLUMN_SEPARATOR } from './helm';
import { Errorable, failed } from './errorable';
import { parseLineOutput } from './outputUtils';
import { affectsUs } from './components/config/config';
import { Dictionary } from './utils/dictionary';
import { assetUri } from './assets';

export const HELM_EXPLORER_NODE_CATEGORY = 'helm-explorer-node';

export function create(host: Host): HelmRepoExplorer {
    return new HelmRepoExplorer(host);
}

export enum RepoExplorerObjectKind {
    Repo,
    Chart,
    ChartVersion,
    Error,
}

export interface HelmObject {
    readonly nodeCategory: 'helm-explorer-node';
    readonly kind: RepoExplorerObjectKind;
    getChildren(): Promise<HelmObject[]>;
    getTreeItem(): vscode.TreeItem;
}

export interface HelmRepo extends HelmObject {
    readonly name: string;
}

export interface HelmRepoChart extends HelmObject {
    readonly id: string;
}

export interface HelmRepoChartVersion extends HelmObject {
    readonly id: string;
    readonly version: string;
}

export function isHelmRepo(o: HelmObject | null | undefined): o is HelmRepo {
    return !!o && o.kind === RepoExplorerObjectKind.Repo;
}

export function isHelmRepoChart(o: HelmObject | null | undefined): o is HelmRepoChart {
    return !!o && o.kind === RepoExplorerObjectKind.Chart;
}

export function isHelmRepoChartVersion(o: HelmObject | null | undefined): o is HelmRepoChartVersion {
    return !!o && o.kind === RepoExplorerObjectKind.ChartVersion;
}

export class HelmRepoExplorer implements vscode.TreeDataProvider<HelmObject> {
    private onDidChangeTreeDataEmitter: vscode.EventEmitter<HelmObject | undefined> = new vscode.EventEmitter<HelmObject | undefined>();
    readonly onDidChangeTreeData: vscode.Event<HelmObject | undefined> = this.onDidChangeTreeDataEmitter.event;

    constructor(host: Host) {
        host.onDidChangeConfiguration((change) => {
            if (affectsUs(change)) {
                this.refresh();
            }
        });
    }

    getTreeItem(element: HelmObject): vscode.TreeItem | Thenable<vscode.TreeItem> {
        return element.getTreeItem();
    }

    getChildren(parent?: HelmObject): vscode.ProviderResult<HelmObject[]> {
        if (parent) {
            return parent.getChildren();
        }

        return this.getHelmRepos();
    }

    private async getHelmRepos(): Promise<HelmObject[]> {
        const repos = await listHelmRepos();
        if (failed(repos)) {
            return [ new HelmError('Unable to list Helm repos', repos.error[0]) ];
        }
        return repos.result;
    }

    async refresh(): Promise<void> {
        await helm.helmExecAsync('repo update');
        this.onDidChangeTreeDataEmitter.fire(undefined);
    }
}

class HelmExplorerNodeImpl {
    readonly nodeCategory = HELM_EXPLORER_NODE_CATEGORY;
}

class HelmError extends HelmExplorerNodeImpl implements HelmObject {
    constructor(private readonly text: string, private readonly detail: string) {
        super();
    }

    get kind() { return RepoExplorerObjectKind.Error; }

    getTreeItem(): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(this.text);
        treeItem.tooltip = 'Click for details';
        treeItem.command = {
            title: 'Show details',
            command: 'extension.showInfoMessage',
            arguments: [this.detail]
        };
        return treeItem;
    }

    async getChildren(): Promise<HelmObject[]> {
        return [];
    }
}

class HelmRepoImpl extends HelmExplorerNodeImpl implements HelmRepo {
    constructor(readonly name: string) {
        super();
    }

    get kind() { return RepoExplorerObjectKind.Repo; }

    getTreeItem(): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(this.name, vscode.TreeItemCollapsibleState.Collapsed);
        treeItem.iconPath = {
            light: assetUri("images/light/helm-blue-vector.svg"),
            dark: assetUri("images/dark/helm-white-vector.svg"),
        };
        treeItem.contextValue = 'vsKubernetes.repo';
        return treeItem;
    }

    async getChildren(): Promise<HelmObject[]> {
        const charts = await listHelmRepoCharts(this.name);
        if (failed(charts)) {
            return [ new HelmError('Error fetching charts', charts.error[0]) ];
        }
        return charts.result;
    }
}

class HelmRepoChartImpl extends HelmExplorerNodeImpl implements HelmRepoChart {
    private readonly versions: HelmRepoChartVersionImpl[];
    private readonly name: string;

    constructor(repoName: string, readonly id: string, content: { [key: string]: string }[]) {
        super();
        this.versions = content.map((e) => new HelmRepoChartVersionImpl(
            id,
            e['chart version'],
            e['app version'],
            e.description
        ));
        this.name = id.substring(repoName.length + 1);
    }

    get kind() { return RepoExplorerObjectKind.Chart; }

    getTreeItem(): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(this.name, vscode.TreeItemCollapsibleState.Collapsed);
        treeItem.contextValue = 'vsKubernetes.chart';
        return treeItem;
    }

    async getChildren(): Promise<HelmObject[]> {
        return this.versions;
    }
}

class HelmRepoChartVersionImpl extends HelmExplorerNodeImpl implements HelmRepoChartVersion {
    constructor(
        readonly id: string,
        readonly version: string,
        private readonly appVersion: string | undefined,
        private readonly description: string | undefined
    ) {
        super();
    }

    get kind() { return RepoExplorerObjectKind.ChartVersion; }

    getTreeItem(): vscode.TreeItem {
        const treeItem = new vscode.TreeItem(this.version);
        treeItem.tooltip = this.tooltip();
        treeItem.command = {
            command: "extension.helmInspectChart",
            title: "Inspect",
            arguments: [this]
        };
        treeItem.contextValue = 'vsKubernetes.chartversion';
        return treeItem;
    }

    async getChildren(): Promise<HelmObject[]> {
        return [];
    }

    private tooltip(): string {
        const tooltipLines: string[] = [ this.description ? this.description : 'No description available'];
        if (this.appVersion) {
            tooltipLines.push(`App version: ${this.appVersion}`);
        }
        return tooltipLines.join('\n');
    }
}

async function listHelmRepos(): Promise<Errorable<HelmRepoImpl[]>> {
    const sr = await helm.helmExecAsync("repo list");
    // TODO: prompt to run 'helm init' here if needed...
    if (!sr || sr.code !== 0) {
        return { succeeded: false, error: [sr ? sr.stderr : "Unable to run Helm"] };
    }

    const repos = sr.stdout.split('\n')
                           .slice(1)
                           .map((l) => l.trim())
                           .filter((l) => l.length > 0)
                           .map((l) => l.split('\t').map((bit) => bit.trim()))
                           .map((bits) => new HelmRepoImpl(bits[0]));
    return { succeeded: true, result: repos };
}

async function listHelmRepoCharts(repoName: string): Promise<Errorable<HelmRepoChartImpl[]>> {
    const syntaxVersion = await helm.helmSyntaxVersion();
    const searchCmd = (syntaxVersion === helm.HelmSyntaxVersion.V3) ? 'search repo' : 'search';
    const sr = await helm.helmExecAsync(`${searchCmd} ${repoName}/ -l`);
    if (!sr || sr.code !== 0) {
        return { succeeded: false, error: [ sr ? sr.stderr : "Unable to run Helm" ]};
    }

    const lines = sr.stdout.split('\n')
                           .map((l) => l.trim())
                           .filter((l) => l.length > 0);
    const rawEntries = parseLineOutput(lines, HELM_OUTPUT_COLUMN_SEPARATOR);

    // Charts can embed newlines in their descriptions. We need to merge
    // 'entries' that are actually continuations with their 'parents.'
    const entries = mergeContinuationEntries(rawEntries);

    const charts = _.chain(entries)
                    .groupBy((e) => e.name)
                    .toPairs()
                    .map((p) => new HelmRepoChartImpl(repoName, p[0], p[1]))
                    .value();
    return { succeeded: true, result: charts };
}

function mergeContinuationEntries(entries: Dictionary<string>[]): Dictionary<string>[] {
    const result = Array.of<Dictionary<string>>();
    for (const entry of entries) {
        if (Object.keys(entry).length === 1) {
            // It's a continuation - merge it with the last entry that wasn't a continuation
            mergeEntry(result[result.length - 1], entry);
        } else {
            // It's a new entry - push it
            result.push(entry);
        }
    }
    return result;
}

function mergeEntry(mergeInto: Dictionary<string>, mergeFrom: Dictionary<string>): void {
    // Because we trim the output lines, continuation descriptions land in
    // the 'name' field
    mergeInto['description'] = `${mergeInto['description'].trim()} ${mergeFrom['name']}`;
}
