// Cross-resource-group role assignment: grants AcrPull on a target ACR to a principal.
// Invoked as a module from main.bicep when the Container App pulls from a private ACR
// in a different resource group than the app itself.

@description('Name of the existing ACR to grant AcrPull on.')
param acrName string

@description('Principal ID (UAMI principalId) to receive the AcrPull role.')
param principalId string

var roleAcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: acr
  name: guid(acr.id, principalId, roleAcrPull)
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
  }
}
