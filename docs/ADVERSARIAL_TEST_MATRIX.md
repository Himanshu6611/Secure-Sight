# Adversarial test matrix

2026-10-09, local Windows: baseline 757 passed; targeted 39 passed; final 796 passed, 0 failures/errors, 0 skips, 26 warnings. No retries or expected-failure suppression. Evidence: `reports/phase15_20261009/`.

Keyword-indexed references below overlap categories and are not unique coverage percentages. Actual JUnit names/statuses are authoritative.

## URL/SSRF/DNS

34 matching executed cases.

- `tests.redirect.test_redirects.test_dns_rebinding_revalidated_and_socket_pinned`
- `tests.test_phase13_security.test_provider_redirect_blocks_private_before_second_socket[127.0.0.1]`
- `tests.test_phase13_security.test_provider_redirect_blocks_private_before_second_socket[169.254.169.254]`
- `tests.test_phase13_security.test_provider_redirect_blocks_private_before_second_socket[::1]`
- `tests.test_phase13_security.test_provider_redirect_blocks_private_before_second_socket[fe80::1]`
- `tests.test_phase13_security.test_provider_redirect_blocks_private_before_second_socket[224.0.0.1]`
- `tests.test_phase13_security.test_provider_redirect_blocks_private_before_second_socket[100.64.0.1]`
- `tests.test_phase13_security.test_pinned_gateway_rechecks_every_answer_and_does_not_reresolve`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://127.1/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://2130706433/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://0177.0.0.1/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://0x7f000001/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://[::1]/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://[::ffff:127.0.0.1]/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://[64:ff9b::7f00:1]/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[http://169.254.169.254/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[https://public.example@127.0.0.1/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[https://example.com\\@127.0.0.1/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[https://example.com:8080/]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[file:///test]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[javascript:alert(1)]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[https://example.com/%0d%0aHeader:x]`
- `tests.test_phase15_adversarial.test_ambiguous_or_restricted_targets[https://example.com/%zz]`
- `tests.test_phase15_adversarial.test_mixed_answers_block_before_pool[127.0.0.1]`
- `tests.test_phase15_adversarial.test_mixed_answers_block_before_pool[10.1.2.3]`
- `tests.test_phase15_adversarial.test_mixed_answers_block_before_pool[169.254.169.254]`
- `tests.test_phase15_adversarial.test_mixed_answers_block_before_pool[::1]`
- `tests.test_phase15_adversarial.test_mixed_answers_block_before_pool[fc00::1]`
- `tests.test_phase15_adversarial.test_mixed_answers_block_before_pool[::ffff:8.8.8.8]`
- `tests.test_remediation.test_pinned_pool_never_delegates_hostname_connect`
- `tests.test_remediation.test_get_redirect_to_private_dns_never_opens_second_connection`
- `tests.test_security.test_dns_mixed_addresses_rejected`
- `tests.test_security.test_head_pins_ip_preserves_tls_and_never_redirects`
- `tests.test_security.test_private_dns_blocks_before_connection`

## MIME/attachments

13 matching executed cases.

- `tests.test_phase10_media.test_mime_mismatch[PNG]`
- `tests.test_phase10_media.test_mime_mismatch[JPEG]`
- `tests.test_phase10_media.test_mime_mismatch[WEBP]`
- `tests.test_phase11_email.test_mime_depth_limit`
- `tests.test_phase11_email.test_received_private_ips_and_chronology`
- `tests.test_phase11_email.test_dangerous_attachment_observed[invoice.pdf.exe-MZbinary]`
- `tests.test_phase11_email.test_dangerous_attachment_observed[../../file.png-MZbinary]`
- `tests.test_phase11_email.test_dangerous_attachment_observed[file.docm-OLE]`
- `tests.test_phase11_email.test_zip_bomb_traversal_nested_and_macro`
- `tests.test_phase15_adversarial.test_nested_mime_is_bounded_before_tree[10-multipart]`
- `tests.test_phase15_adversarial.test_nested_mime_is_bounded_before_tree[1200-multipart]`
- `tests.test_phase15_adversarial.test_nested_mime_is_bounded_before_tree[1200-message]`
- `tests.test_phase15_adversarial.test_bounded_parser_mutations`

## Media

17 matching executed cases.

- `tests.test_phase10_media.test_decoder_dimensions[size0]`
- `tests.test_phase10_media.test_decoder_dimensions[size1]`
- `tests.test_phase10_media.test_decoder_dimensions[size2]`
- `tests.test_phase10_media.test_real_ocr`
- `tests.test_phase10_media.test_real_multi_qr`
- `tests.test_phase10_media.test_c2pa_unsigned_and_unknown_parse`
- `tests.test_phase10_media.test_real_c2pa_valid_untrusted_and_tampered`
- `tests.test_phase10_media.test_multilingual_ocr_real`
- `tests.test_phase10_media.test_xmp_external_entities_not_interpreted`
- `tests.test_phase10_media.test_animated_media_rejected`
- `tests.test_phase10_media.test_ocr_and_qr_failures_are_explicit`
- `tests.test_phase12_dashboard.test_real_email_qr_website_unified_workspace`
- `tests.test_phase13_security.test_upload_extension_magic_mismatch_before_decoder[image.exe]`
- `tests.test_phase13_security.test_upload_extension_magic_mismatch_before_decoder[image.svg]`
- `tests.test_phase13_security.test_upload_extension_magic_mismatch_before_decoder[image.jpg]`
- `tests.test_phase13_security.test_upload_extension_magic_mismatch_before_decoder[image]`
- `tests.test_phase15_adversarial.test_bounded_media_mutations`

## Dashboard/evidence/auth

60 matching executed cases.

- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://paypal.com-<title>PayPal</title><h1>PayPal login</h1><input type="password">]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://paypal.es-<title>PayPal</title><h1>PayPal</h1><input type="password">]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://login.microsoftonline.com-<title>Microsoft</title><h1>Microsoft</h1><input type="password">]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://new-startup.example-<title>New startup</title><input type="password">]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://community.example-<title>PayPal integration guide</title><p>PayPal API documentation</p>]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://partner.example-<title>Microsoft</title><h1>Microsoft</h1><form action="https://login.microsoftonline.com/login"><input type="password"></form>]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://paypal-partner.example-<title>PayPal</title><h1>PayPal authorized reseller</h1><input type="password">]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://xn--bcher-kva.example-<title>International bookstore</title><input type="password">]`
- `tests.brand.test_intelligence.test_benign_or_insufficient_evidence_has_no_brand_risk[https://paypa1.example-<title>PayPal</title><input type="password">]`
- `tests.brand.test_intelligence.test_jsonld_injection_and_prompt_text_not_in_evidence`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[signal_id-invented.reason]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[source-invented]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[value-<script>alert(1)</script>]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[normalized_value-nan]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[contribution--1]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[confidence-inf]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[severity-CRITICAL]`
- `tests.explanation.test_engine.test_invalid_evidence_omitted[value-value7]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[dns]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[tls]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[registration]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[reputation]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[html]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[content]`
- `tests.risk.test_engine.test_missing_evidence_not_safe[ml]`
- `tests.risk.test_engine.test_double_count_prevention_and_audit_reconstruction`
- `tests.risk.test_engine.test_integrated_api_canonical_assessment_and_safe_audit_log`
- `tests.test_phase11_email.test_poisoned_email_evidence_rejected`
- `tests.test_phase12_dashboard.test_authentication_required[/api/v1/dashboard/audit]`
- `tests.test_phase12_dashboard.test_cross_tenant_idor[]`
- `tests.test_phase12_dashboard.test_cross_tenant_idor[/evidence]`
- `tests.test_phase12_dashboard.test_cross_tenant_idor[/timeline]`
- `tests.test_phase12_dashboard.test_cross_tenant_idor[/graph]`
- `tests.test_phase12_dashboard.test_cross_tenant_idor[/export]`
- `tests.test_phase12_dashboard.test_real_login_csrf_logout_and_expiry`
- `tests.test_phase12_dashboard.test_server_roles_deactivation_and_export`
- `tests.test_phase12_dashboard.test_api_client_bearer_no_cookie_or_csrf`
- `tests.test_phase12_dashboard.test_evidence_graph_timeline_pagination`
- `tests.test_phase12_dashboard.test_cases_notes_evidence_feedback_and_no_score_mutation`
- `tests.test_phase12_dashboard.test_cross_tenant_case_link_rejected`
- `tests.test_phase12_dashboard.test_audit_integrity_and_admin_scope`
- `tests.test_phase12_dashboard.test_private_purge_cli_removes_content_preserves_audit`
- `tests.test_phase13_security.test_unicode_csrf_and_bad_bearer_fail_closed`
- `tests.test_phase13_security.test_private_mass_assignment[extra0]`
- `tests.test_phase13_security.test_private_mass_assignment[extra1]`
- `tests.test_phase13_security.test_private_mass_assignment[extra2]`
- `tests.test_phase13_security.test_private_mass_assignment[extra3]`
- `tests.test_phase14_quality.test_gate_failures_and_optional_evidence_are_distinct`
- `tests.test_phase14_quality.test_cross_phase_contract_and_export_immutability`
- `tests.test_phase15_adversarial.test_foreign_export_and_evidence_are_not_visible[/graph]`
- `tests.test_phase15_adversarial.test_foreign_export_and_evidence_are_not_visible[/timeline]`
- `tests.test_phase15_adversarial.test_foreign_export_and_evidence_are_not_visible[/evidence]`
- `tests.test_phase15_adversarial.test_foreign_export_and_evidence_are_not_visible[/export?format=json]`
- `tests.test_phase15_adversarial.test_case_cannot_overwrite_backend_scoring[risk]`
- `tests.test_phase15_adversarial.test_case_cannot_overwrite_backend_scoring[verdict]`
- `tests.test_phase15_adversarial.test_case_cannot_overwrite_backend_scoring[confidence]`
- `tests.test_phase15_adversarial.test_case_cannot_overwrite_backend_scoring[role]`
- `tests.test_phase15_adversarial.test_case_cannot_overwrite_backend_scoring[tenant]`
- `tests.test_phase15_adversarial.test_case_cannot_overwrite_backend_scoring[evidence]`
- `tests.test_remediation.test_scan_decisions_use_observed_web_evidence`

## Resources/outages

51 matching executed cases.

- `tests.behavior.test_behavior.test_failure_and_loop_never_legitimate`
- `tests.behavior.test_behavior.test_configuration_rejects_unsafe_or_unbounded[total_timeout_seconds-inf]`
- `tests.brand.test_intelligence.test_config_rejects_budget_expansion[total_timeout_seconds-True]`
- `tests.explanation.test_engine.test_failure_is_explained`
- `tests.explanation.test_engine.test_invalid_context_has_bounded_failure[None]`
- `tests.explanation.test_engine.test_invalid_context_has_bounded_failure[bad1]`
- `tests.explanation.test_engine.test_invalid_context_has_bounded_failure[bad2]`
- `tests.explanation.test_engine.test_invalid_context_has_bounded_failure[bad3]`
- `tests.explanation.test_engine.test_timeout_information_preserved`
- `tests.historical.test_history.test_rdap_failure_uses_actual_whois_parser`
- `tests.historical.test_history.test_partial_rdap_retained_if_whois_cannot_supply_creation`
- `tests.redirect.test_redirects.test_transport_failures[error0-DNS_FAILED]`
- `tests.redirect.test_redirects.test_transport_failures[error1-TIMEOUT]`
- `tests.redirect.test_redirects.test_transport_failures[error2-DNS_FAILED]`
- `tests.risk.test_engine.test_partial_content_not_counted_as_completed`
- `tests.risk.test_engine.test_scoring_failure_integration_cannot_be_green`
- `tests.test_domain_intelligence.TestTLSIntelligence.test_tls_timeout`
- `tests.test_phase10_media.test_media_api_worker_and_unknown`
- `tests.test_phase10_media.test_worker_wall_timeout_and_cleanup`
- `tests.test_phase10_media.test_worker_output_limit`
- `tests.test_phase10_media.test_worker_memory_limit`
- `tests.test_phase10_media.test_ocr_and_qr_failures_are_explicit`
- `tests.test_phase10_media.test_linked_failure_propagates`
- `tests.test_phase10_media.test_invalid_source_api_failure`
- `tests.test_phase10_media.test_worker_cpu_limit`
- `tests.test_phase11_email.test_async_api_token_and_failure_safety`
- `tests.test_phase11_email.test_job_queue_backpressure_and_expiry`
- `tests.test_phase11_email.test_production_redis_encryption_cross_worker_and_capacity`
- `tests.test_phase11_email.test_job_store_failure_releases_capacity`
- `tests.test_phase11_email.test_dmarc_invalid_policy_and_dns_failure`
- `tests.test_phase12_dashboard.test_missing_probability_not_safe[PARTIAL]`
- `tests.test_phase12_dashboard.test_worker_start_failure_releases_capacity`
- `tests.test_phase13_security.test_authorization_precedes_busy_capacity[viewer]`
- `tests.test_phase13_security.test_authorization_precedes_busy_capacity[analyst]`
- `tests.test_phase13_security.test_actor_and_failure_logging_are_content_free`
- `tests.test_phase13_security.test_provider_circuit_opens_recovers_and_bounds_memory`
- `tests.test_phase13_security.test_worker_env_workspace_cleanup_and_no_persistence`
- `tests.test_phase13_security.test_linked_worker_configuration_contains_no_service_secrets`
- `tests.test_phase13_security.test_worker_start_failure_cleans_private_workspace`
- `tests.test_phase13_security.test_partial_intelligence_never_authorizes_legitimate[reputation]`
- `tests.test_phase13_security.test_partial_intelligence_never_authorizes_legitimate[registration]`
- `tests.test_phase13_security.test_partial_intelligence_never_authorizes_legitimate[html]`
- `tests.test_phase13_security.test_partial_intelligence_never_authorizes_legitimate[ml]`
- `tests.test_phase14_quality.test_gate_failures_and_optional_evidence_are_distinct`
- `tests.test_remediation.test_partial_providers_cannot_announce_safe`
- `tests.test_remediation.test_all_heavy_endpoints_share_capacity[/api/v1/features/url]`
- `tests.test_remediation.test_all_heavy_endpoints_share_capacity[/api/v1/intelligence/domain]`
- `tests.test_remediation.test_all_heavy_endpoints_share_capacity[/api/v1/analyze/webpage]`
- `tests.test_remediation.test_all_heavy_endpoints_share_capacity[/api/v1/ml/predict]`
- `tests.test_security.test_production_headers_and_backend_failure`
- `tests.test_security.test_capacity_released`

## Risk/history/metamorphic

56 matching executed cases.

- `tests.behavior.test_behavior.test_chain_deduplication_no_extra_risk`
- `tests.brand.test_intelligence.test_config_rejects_budget_expansion[history_max_entries-0]`
- `tests.brand.test_intelligence.test_config_rejects_budget_expansion[history_scope-persistent]`
- `tests.explanation.test_engine.test_contradictions_preserved[0.99-SAFE]`
- `tests.explanation.test_engine.test_contradictions_preserved[0.02-MALICIOUS]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[None]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[garbage]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[2020-01-01]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[2100-01-01T00:00:00Z]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[1900-01-01T00:00:00Z]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[<script>]`
- `tests.historical.test_history.test_invalid_registration_dates_unknown[2020-99-99T00:00:00Z]`
- `tests.historical.test_history.test_only_registration_event_defines_age`
- `tests.historical.test_history.test_rdap_normalization_privacy_and_identity`
- `tests.historical.test_history.test_rdap_iana_discovery_and_cache_provenance`
- `tests.historical.test_history.test_bad_bootstrap_private_provider_rejected`
- `tests.historical.test_history.test_json_gateway_rejects_unsafe_responses[spec0]`
- `tests.historical.test_history.test_json_gateway_rejects_unsafe_responses[spec1]`
- `tests.historical.test_history.test_json_gateway_rejects_unsafe_responses[spec2]`
- `tests.historical.test_history.test_json_gateway_rejects_unsafe_responses[spec3]`
- `tests.historical.test_history.test_json_gateway_rejects_unsafe_responses[spec4]`
- `tests.historical.test_history.test_json_gateway_deadline_and_redirect_count`
- `tests.historical.test_history.test_first_seen_separate_pages_and_retention`
- `tests.historical.test_history.test_sensitive_urls_not_indexed_and_no_raw_paths_stored`
- `tests.historical.test_history.test_old_domain_recent_page_not_repurposing_and_changes_not_compromise`
- `tests.historical.test_history.test_current_dns_tls_metadata_differences_are_not_archive_history`
- `tests.historical.test_history.test_rdap_failure_uses_actual_whois_parser`
- `tests.historical.test_history.test_partial_rdap_retained_if_whois_cannot_supply_creation`
- `tests.historical.test_history.test_whois_future_date_is_not_zero_day_registration`
- `tests.historical.test_history.test_json_gateway_success_and_no_authentication`
- `tests.redirect.test_redirects.test_loop_duplicate_and_fragment_normalization[https://example.com/]`
- `tests.redirect.test_redirects.test_loop_duplicate_and_fragment_normalization[https://example.com/#different]`
- `tests.risk.test_engine.test_normalization[True-boolean-1]`
- `tests.risk.test_engine.test_normalization[False-boolean-0]`
- `tests.risk.test_engine.test_normalization[0-inverse_boolean-1]`
- `tests.risk.test_engine.test_normalization[1-inverse_boolean-0]`
- `tests.risk.test_engine.test_normalization[4-ramp-0.4]`
- `tests.risk.test_engine.test_normalization[12-ramp-1]`
- `tests.risk.test_engine.test_normalization[4-inverse_ramp-0.6]`
- `tests.risk.test_engine.test_normalization[0-inverse_ramp-1]`
- `tests.risk.test_engine.test_normalization[0.91-probability-0.91]`
- `tests.risk.test_engine.test_normalization[None-probability-None]`
- `tests.test_phase12_dashboard.test_real_login_csrf_logout_and_expiry`
- `tests.test_phase12_dashboard.test_failed_async_analysis_is_private_history`
- `tests.test_phase14_quality.test_domain_age_alone_is_not_phishing[0]`
- `tests.test_phase14_quality.test_domain_age_alone_is_not_phishing[1]`
- `tests.test_phase14_quality.test_domain_age_alone_is_not_phishing[30]`
- `tests.test_phase14_quality.test_domain_age_alone_is_not_phishing[365]`
- `tests.test_phase14_quality.test_domain_age_alone_is_not_phishing[9000]`
- `tests.test_phase14_quality.test_url_normalization_idempotence[https://EXAMPLE.com/]`
- `tests.test_phase14_quality.test_url_normalization_idempotence[https://\u4f8b\u3048.jp/a%20b]`
- `tests.test_phase14_quality.test_url_normalization_idempotence[https://example.com/?x=%27]`
- `tests.test_phase14_quality.test_future_history_is_excluded_without_rewriting_future`
- `tests.test_phase15_adversarial.test_normalized_security_policy_is_idempotent[https://EXAMPLE.com./a/../b?q=%252f#safe]`
- `tests.test_phase15_adversarial.test_normalized_security_policy_is_idempotent[https://\u4f8b\u3048.jp/]`
- `tests.test_phase15_adversarial.test_normalized_security_policy_is_idempotent[https://example.com/?next=http%3A%2F%2F127.0.0.1]`

Untested: live CNAME/rebinding infrastructure, real browser navigation/download/popups (browser execution is disabled), production concurrent load/native sandbox escape, complete browser XSS/accessibility execution, prospective model accuracy and genuine/manipulated deepfake ground truth. Synthetic tests and code review do not establish those controls.
