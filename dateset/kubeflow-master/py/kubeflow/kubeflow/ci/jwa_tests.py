""""Argo Workflow for testing Jupyter Web App"""
from kubeflow.kubeflow.ci import workflow_utils
from kubeflow.testing import argo_build_util


class Builder(workflow_utils.ArgoTestBuilder):
    def __init__(self, name=None, namespace=None, bucket=None,
                 test_target_name=None, **kwargs):
        super().__init__(name=name, namespace=namespace, bucket=bucket,
                         test_target_name=test_target_name, **kwargs)

    def _kustomize_build_task(self, task_template):
        k_build = argo_build_util.deep_copy(task_template)

        k_build["name"] = "kustomize-build-test"
        k_build["container"]["image"] = "k8s.gcr.io/kustomize/kustomize:v4.1.2"
        k_build["container"]["args"] = ["build"]

        manifest_dir = ("%s/components/crud-web-apps/jupyter/manifests/"
                        "overlays/istio/") % self.src_dir
        k_build["container"]["workingDir"] = manifest_dir

        return k_build

    def build(self):
        """Build the Argo workflow graph"""
        workflow = self.build_init_workflow(exit_dag=False)
        task_template = self.build_task_template()
        app_dir = "%s/components/crud-web-apps/jupyter" % self.src_dir

        # build manifests with kustomize
        kustomize_build_task = self._kustomize_build_task(task_template)
        argo_build_util.add_task_to_dag(workflow, workflow_utils.E2E_DAG_NAME,
                                        kustomize_build_task,
                                        [self.mkdir_task_name])

        # Test build JWA image using Kaniko
        dockerfile = "%s/Dockerfile" % app_dir
        context = "dir://%s/components/crud-web-apps" % self.src_dir
        destination = "jwa-test"

        kaniko_task = self.create_kaniko_task(task_template, dockerfile,
                                              context, destination,
                                              no_push=True)
        argo_build_util.add_task_to_dag(workflow,
                                        workflow_utils.E2E_DAG_NAME,
                                        kaniko_task, [self.mkdir_task_name])

        # install npm modules
        ui_dir = "%s/frontend" % app_dir
        modules_install_task = self.create_install_modules_task(task_template,
                                                                ui_dir)
        argo_build_util.add_task_to_dag(workflow, workflow_utils.E2E_DAG_NAME,
                                        modules_install_task,
                                        [self.mkdir_task_name])

        # check if the frontend code is properly formatted
        format_typescript = self.create_format_typescript_task(task_template,
                                                               ui_dir)
        argo_build_util.add_task_to_dag(workflow,
                                        workflow_utils.E2E_DAG_NAME,
                                        format_typescript,
                                        [modules_install_task["name"]])

        # check if the backend python code is properly formatted
        backend_dir = "%s/backend" % app_dir
        format_python = self.create_format_python_task(task_template,
                                                       backend_dir)
        argo_build_util.add_task_to_dag(workflow,
                                        workflow_utils.E2E_DAG_NAME,
                                        format_python,
                                        [self.mkdir_task_name])

        # Set the labels on all templates
        workflow = argo_build_util.set_task_template_labels(workflow)

        return workflow


def create_workflow(name=None, namespace=None, bucket=None, **kwargs):
    """
    Args:
        name: Name to give to the workflow. This can also be used to name
              things associated with the workflow.
    """
    builder = Builder(name=name, namespace=namespace, bucket=bucket, **kwargs)

    return builder.build()
