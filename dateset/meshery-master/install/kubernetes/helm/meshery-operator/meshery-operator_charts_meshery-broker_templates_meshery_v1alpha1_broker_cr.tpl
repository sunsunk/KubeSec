# Source: meshery-operator/charts/meshery-broker/templates/meshery_v1alpha1_broker_cr.tpl
apiVersion: meshery.layer5.io/v1alpha1
kind: Broker
metadata:
  name: meshery-broker
  namespace: default
spec:
  size: 1
