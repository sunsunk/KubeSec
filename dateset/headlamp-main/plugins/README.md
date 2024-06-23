# Plugins

## Quickstart for running an example plugin

To see "Pods: x" in the header of Headlamp run this example plugin:

```bash
cd plugins/examples/pod-counter
npm install
npm start
```

## Plugin documentation

See the [Headlamp plugins documentation on the web](
https://headlamp.dev/docs/latest/development/plugins/) 
or in this repo at 
[../docs/development/plugins/](../docs/development/plugins/).

There you will see detailed API documentation, examples, and guides on how to develop plugins.


## The example plugins

Folder                                         | Description
------                                         | -----------
[examples/](examples)                          | Examples folder.
[examples/app-menus](examples/app-menus)       | Add app window menus.
[examples/change-logo](examples/change-logo)   | Change the logo.
[examples/cluster-chooser](examples/cluster-chooser)   | Override default chooser button.
[examples/details-view](examples/details-view)         | Custom sections and actions for detail views.
[examples/dynamic-clusters](examples/dynamic-clusters) | Update cluster configuration dynamically.
[examples/pod-counter](examples/pod-counter)   | Display number of Pods in title bar.
[examples/sidebar](examples/sidebar)           | Change the side bar menu.
[examples/tables](examples/tables)             | Override the tables in list views.
headlamp-plugin               | headlamp-plugin script which plugins use.
headlamp-plugin/template      | Template for new Headlamp plugins.
