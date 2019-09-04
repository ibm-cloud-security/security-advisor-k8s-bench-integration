
set -x
accountid=$1
apikey=$2
clustername=$3
kubeconfigname=$4
echo "CLOUD_ENV is $CLOUD_ENV"

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
echo "starting to prepare kubebench analysis report"
kubectl logs -f "$(kubectl get pods |grep kube-bench-public | awk '{ print $1 }')" >> ../vul.txt
echo "analysis report prepared"
echo "Uploading report to SA"

cd ../kubebench-sa-adapter/$CLOUD_ENV
python kubeBenchAdaptor.py $accountid $apikey $clustername $SA_ENDPOINT