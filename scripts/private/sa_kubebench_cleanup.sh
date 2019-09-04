
set +x
if [ "$#" -ne 5 ]; then
    echo "Required arguments missing!"
    echo "Usage : ./$(basename "$0") <account id> <api key> <full path to directory of kube configs> <cloud-env> <sa-endpoint>"
    exit 1
fi

account_id=$1
api_key=$2
kube_config_dir=$3
sa_endpoint=$4
cloud_env=$5

kubeconfig_name=$(ls $kube_config_dir |grep yml)

python src/$cloud_env/kubeBenchCleanup.py $account_id $api_key $sa_endpoint

kubectl delete secret kubebench-private-secret
kubectl delete secret kubebench-private-credentials
helm del --purge kubebench-sa-adapter-private
podname=$(kubectl get job |grep kubebench-sa-adapter|awk '{ print $1 }')
kubectl delete job $podname

# Delete kube-bench Job running on target cluster: 
export KUBECONFIG=$kube_config_dir/$kubeconfig_name
kubectl delete job kube-bench
