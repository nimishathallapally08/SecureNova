exports.onExecutePostLogin = async (event, api) => {
  const impossibleTravel = event.request.ip && event.user.last_ip &&
    event.request.ip !== event.user.last_ip; // simplified example condition
  if (event.user.app_metadata?.risk_flag === true) {
    api.access.deny("Login blocked by risk policy");
  }
};