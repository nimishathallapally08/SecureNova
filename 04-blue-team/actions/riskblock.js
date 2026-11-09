exports.onExecutePostLogin = async (event, api) => {
  const metadata = event.user.app_metadata || {};
  const riskScore = metadata.securenova_risk_score;
  const highRisk = metadata.securenova_risk === "high";
  const elevatedScore = typeof riskScore === "number" && riskScore >= 80;

  if (highRisk || elevatedScore) {
    api.access.deny("Login blocked by the SecureNova risk policy.");
  }
};