#ability to move managed disks needs to be registered
az feature register --namespace Microsoft.Compute --name ManagedResourcesMove

#check status of registration by running and wait for state = Registered:
az feature show --namespace Microsoft.Compute --name ManagedResourcesMove

#Microsoft recommends re-registering Compute Space afterwards
az provider register --namespace Microsoft.Compute

#finally go into your GUI, resource group, Move Resources and you will now be able to move managed disks and compute resources