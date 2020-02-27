#*******************************************************************************
# * Licensed Materials - Property of IBM
# * IBM Bluemix Container Service, 5737-D43
# * (C) Copyright IBM Corp. 2020 All Rights Reserved.
# * US Government Users Restricted Rights - Use, duplication or 
# * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
#******************************************************************************

accountid=$1
apikey=$2
clustername=$3
kubeconfigname=$4

git clone https://github.com/aquasecurity/kube-bench.git
cd kube-bench/
rm job.yaml
cd ..
cd kubebench-sa-adapter/$CLOUD_ENV
cp job.yaml ../../kube-bench/
cd ../../kube-bench

export KUBECONFIG=/etc/kubeconfig/$kubeconfigname
kubectl apply -f job.yaml
sleep 20
echo "starting to prepare kubebench analysis report..."
kubectl logs -f "$(kubectl get pods |grep kube-bench-public | awk '{ print $1 }')" >> ../vul.txt
echo "analysis report prepared!"
echo "uploading report to SA..."

cd ../kubebench-sa-adapter/$CLOUD_ENV
python3 kubeBenchAdaptor.py $accountid $apikey $clustername $SA_ENDPOINT
echo "uploaded kube-bench report to SA"
