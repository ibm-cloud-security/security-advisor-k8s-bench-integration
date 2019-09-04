
set -x
accountid=$1
apikey=$2
clustername=$3
oc_login_apikey=$4
echo "CLOUD_ENV is $CLOUD_ENV"

git clone https://github.com/aquasecurity/kube-bench.git
cd kube-bench/
rm job.yaml
cd ..
cd kubebench-sa-adapter/$CLOUD_ENV
cp job.yaml ../../kube-bench/
cd ../../kube-bench

# export KUBECONFIG=/etc/kubeconfig/$kubeconfigname
ibmcloud login -a test.cloud.ibm.com -r us-south --apikey $oc_login_apikey
ibmcloud oc cluster-get --cluster $clustername

masterURL=$(ibmcloud oc cluster-get --cluster $clustername|grep "Master URL" |awk '{ print $3 }')
echo "masterURL is $masterURL"
oc login -u apikey -p $oc_login_apikey --server=$masterURL
oc apply -f job.yaml

sleep 20
echo "starting to prepare kubebench analysis report"
oc logs -f "$(oc get pods |grep kube-bench-redhat | awk '{ print $1 }')" >> ../vul.txt
echo "analysis report prepared"
echo "Uploading report to SA"

cd ../kubebench-sa-adapter/$CLOUD_ENV
python kubeBenchAdaptor.py $accountid $apikey $clustername $SA_ENDPOINT