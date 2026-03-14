// All components in this file were dead CRS settings that the policy engine
// does not use. They were: AdvancedParanoiaSettings, RequestPolicySettings,
// LimitsSettings, CRSExclusionProfiles, AdvancedCRSControls.
//
// These settings are still in the WAFServiceSettings interface and persisted
// by the backend, but the policy engine ignores them. The UI no longer
// exposes them to avoid confusing users with non-functional controls.
//
// If per-service CRS profiles are re-implemented via the policy engine,
// new components should be created in a fresh file.
