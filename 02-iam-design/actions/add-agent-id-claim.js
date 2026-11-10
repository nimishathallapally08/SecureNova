exports.onExecutePostLogin = async (event, api) => {
 const ns = "https://securenova.ai/";
 const agentId = "agent-" + event.user.user_id.split("|").pop();
 // Namespacing avoids claim collisions; this descriptive value is not authorization.
 api.idToken.setCustomClaim(ns + "agent_id", agentId);
 api.accessToken.setCustomClaim(ns + "agent_id", agentId);
};