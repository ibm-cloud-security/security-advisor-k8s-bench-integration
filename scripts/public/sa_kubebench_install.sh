#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2017 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

<<<<<<< HEAD
set +x
if [ "$#" -ne 4 ]; then
    echo "Required arguments missing!"
=======
# To check if helm is installed on system or not.
command -v helm >/dev/null 2>&1 || { echo >&2 "helm is required. Aborting."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo >&2 "kubectl is required. Aborting."; exit 1; }

# To check what version of helm is installed on system.
helmVer=`helm version --template {{.Version}}`
helmVerMajor="$(cut -d'.' -f 1 <<< ${helmVer:1})"

# CLI Arguments check
if [ "$#" -ne 4 ]; then
    if [ "$#" -lt 4 ]; then
        echo "Required arguments missing!"
    else
        echo "Wrong usage!"
    fi
>>>>>>> c040036... sdk integration complete
    echo "Usage : ./$(basename "$0") <account id> <api key> <cluster name> <full path to directory of kube configs>"
    exit 1
fi

<<<<<<< HEAD
=======
# Arguments assignment
>>>>>>> c040036... sdk integration complete
account_id=$1
api_key=$2
cluster_name=$3
kube_config_dir=$4
kubeconfig_name=$(ls $kube_config_dir |grep yml)

<<<<<<< HEAD
# cd ./src/$environment
chmod +x generate_kubeconfig_secrets.sh
chmod +x generate_kubebench_secrets.sh

./generate_kubeconfig_secrets.sh $kube_config_dir kubebench-public-secret default
./generate_kubebench_secrets.sh $account_id $api_key $cluster_name $kubeconfig_name default

cd ../../config/helm/kubebench-adapter-public
helm install --name kubebench-sa-adapter-public .

=======
# Change mode of scripts for creating kubernetes secrets
chmod +x ./scripts/public/generate_kubeconfig_secrets.sh
chmod +x ./scripts/public/generate_kubebench_secrets.sh

# Execute scripts for creating kubernetes secrets
./scripts/public/generate_kubeconfig_secrets.sh $kube_config_dir kubebench-public-secret default
./scripts/public/generate_kubebench_secrets.sh $account_id $api_key $cluster_name $kubeconfig_name default

# Install helm chart in kubernetes
cd config/helm/kubebench-adapter-public
if [ $helmVerMajor -gt 2 ]; then
    helm install kubebench-sa-adapter-public .
else
    helm install --name kubebench-sa-adapter-public .
fi
>>>>>>> c040036... sdk integration complete
