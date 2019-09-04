def fetchFailureList(fileName):
    issueList=list()
    logData = open(fileName, 'r')
    logData = list(logData)
    remediation=list()
    remePtr=0

    for iter in range(len(logData)):
        if('[FAIL]'in logData[iter] ):
            issueList.append(logData[iter])

        if('== Remediations ==' in logData[iter]):
            remePtr=iter

    remediationList=list()
    remStr=''

    for iter in range(remePtr+1, len(logData)):
        remStr=remStr+logData[iter]+" "
        if (len(logData[iter])==1):
            remediationList.append(remStr)
            remStr = ''
    issuelist = list();
    for issueValue in issueList:
        for s in issueValue.split():
            if(s.replace('.', '1').isdigit() and '.' in s):
                issueNumber=s
                for remValue in remediationList:
                    if (issueNumber in remValue):
                        vulnerability  =  {}
                        vulnerability['issue'] = issueValue;
                        vulnerability['remediation'] = remValue;
                        issuelist.append(vulnerability);
    return issuelist;


def fetchWarningList(fileName):
    issueList=list()
    logData = open(fileName, 'r')
    logData = list(logData)
    remediation=list()
    remePtr=0

    for iter in range(len(logData)):
        if('[WARN]'in logData[iter] ):
            issueList.append(logData[iter])

        if('== Remediations ==' in logData[iter]):
            remePtr=iter

    remediationList=list()
    remStr=''

    for iter in range(remePtr+1, len(logData)):
        remStr=remStr+logData[iter]+" "
        if (len(logData[iter])==1):
            remediationList.append(remStr)
            remStr = ''
    issuelist = list();
    for issueValue in issueList:
        for s in issueValue.split():
            if(s.replace('.', '1').isdigit() and '.' in s):
                issueNumber=s
                for remValue in remediationList:
                    if (issueNumber in remValue):
                        vulnerability = {}
                        vulnerability['issue'] = issueValue;
                        vulnerability['remediation'] = remValue;
                        issuelist.append(vulnerability);
    return issuelist;



