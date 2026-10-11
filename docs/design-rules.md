# Design rules

The secure-design rules this service follows, each with the test that proves it. A test
(`tests/test_design_rules.py`) fails if a named test is renamed or deleted, so this page cannot
claim a rule that nothing checks. To add a rule, add the test first, then a row here.

| Rule | In plain words | Proof |
|---|---|---|
| Deny by default | Every address needs a valid key, except the two health checks. | `tests/test_service_key.py::test_every_protected_route_refuses_every_kind_of_bad_header` |
| Fail closed | If the key setting is missing or unreadable, the service refuses everyone instead of opening up. | `tests/test_service_key.py::test_with_no_key_configured_the_service_refuses_instead_of_opening` |
| Least privilege | Each caller can use only the routes written for it. | `tests/test_caller_permissions.py::test_every_caller_gets_exactly_the_routes_it_is_allowed_on_every_route` |
| Identity from the key alone | A caller cannot claim to be someone else by saying so. | `tests/test_caller_permissions.py::test_a_caller_cannot_borrow_another_callers_rights_by_saying_so` |
| No default secrets | No built-in key works when nothing is configured. | `tests/test_authentication_rules.py::test_there_is_no_built_in_key_that_works_when_nothing_is_configured` |
| Secrets as files | Keys and passwords are read from read-only mounted files, not from the environment. | `tests/test_secret_files.py::test_the_service_key_is_read_from_the_mounted_file` |
| Reveal nothing | An unexpected error gets one fixed reply with nothing from inside. | `tests/test_error_handling.py::test_an_unexpected_error_gets_a_fixed_reply_with_nothing_from_inside` |
| Internal only | Nothing this repo deploys can be reached from outside the cluster. | `tests/test_internal_only.py::test_nothing_this_repo_deploys_can_be_reached_from_outside_the_cluster` |
| Hardened pods | Every pod is locked down: no Kubernetes token, default seccomp, read-only filesystem for our own pods. | `tests/test_pod_hardening.py::test_every_pod_this_repo_deploys_is_locked_down` |
| Pinned supply chain | Every Python library is pinned exactly and checked by hash. | `tests/test_dependency_lock.py::test_every_library_in_a_lock_is_pinned_exactly_and_has_hashes` |
| Pinned images | Every ready-made image is pinned to an exact digest. | `tests/test_image_pins.py::test_every_ready_made_image_in_the_real_files_is_pinned_to_a_digest` |
| Reviewed cryptography | The only cryptography is the reviewed set; anything new is a deliberate change. | `tests/test_cryptography_rules.py::test_application_code_uses_no_unreviewed_cryptography` |
| No dangerous functions | No shell commands, code evaluation or object loading. | `tests/test_forbidden_calls.py::test_application_code_contains_no_forbidden_calls` |
| Checked calls | The type checker finds wrong arguments before the program runs. | `tests/test_type_checking.py::test_the_application_passes_the_type_checker` |
| Settings fixed at deploy | The code cannot change its own settings, and opens no cross-domain or XML door. | `tests/test_configuration_rules.py::test_the_application_code_keeps_its_configuration_fixed_and_opens_no_cross_domain_or_xml_doors` |
| No uploads | The application accepts no uploaded files or forms. | `tests/test_no_file_uploads.py::test_application_code_accepts_no_uploaded_files_or_forms` |
| Validate at every boundary | Every request and message model refuses fields it does not list. | `tests/test_request_fields.py::test_every_model_forbids_extra_fields` |
| History is append-only | A submission can never be changed or removed, only added to. | `tests/test_submissions.py::test_there_is_no_way_to_change_or_remove_a_submission` |
| Steps happen in order | Only a graded submission can be reviewed. | `tests/test_reviews.py::test_only_a_graded_submission_can_be_reviewed` |
