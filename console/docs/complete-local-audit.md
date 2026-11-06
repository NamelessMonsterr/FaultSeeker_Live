# Complete local code audit

Status: IN PROGRESS. No complete audit or chain correctness pass claimed.

Method: direct file review and caller/callee tracing, followed by isolated offline reproductions. No subagents. Review existing defects as well as recent changes. No model runs until audit and justified fixes are tested.

Statuses: pending; reviewed; finding confirmed; hypothesis; fixed and tested; deferred with reason. A test passing does not mark a file reviewed.

## console: 9c8223184df5da882617191636f55542934d5adb

| File | Status | Evidence / findings |
|---|---|---|
| `.dockerignore` | read; cross-module verification pending | Full file read in audit continuation. |
| `.gitattributes` | read; follow-through pending | Full source read; findings and evidence below. |
| `.gitignore` | read; follow-through pending | Full source read; findings and evidence below. |
| `.nojekyll` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `404.html` | read; follow-through pending | Full source read; findings and evidence below. |
| `Dockerfile` | read; cross-module verification pending | Full file read in audit continuation. |
| `NOTICE` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `README.md` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `api/capture` | pending | |
| `api/config` | pending | |
| `app/explorer_trace.py` | read; downstream review pending | All 237 lines read; observations below. |
| `app/function_wall_guard.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `app/model_endpoint.py` | read; reproductions pending | All 587 lines read; missing finish-reason acceptance reproduced offline. |
| `app/model_routes.py` | read; caller review pending | All 117 lines read; routing and adaptation traced into transport and diagnostic. |
| `app/pipeline_guards.py` | read; integration review pending | All 649 lines read; trace/ABI/model/report hooks traced. |
| `app/requirements-app.txt` | read; cross-module verification pending | Full file read in audit continuation. |
| `app/rpc_transport.py` | read; downstream review pending | All 169 lines read; observations below. |
| `app/samples/hedgey_e7c04c6fb037.events.jsonl` | pending | |
| `app/samples/hedgey_e7c04c6fb037.result.json` | pending | |
| `app/server.py` | in progress | All 1491 lines read. Caller/dependency tracing and reproductions pending; findings below. |
| `app/trace_identity.py` | read; downstream review pending | All 97 lines read; observations below. |
| `app/verified_abi_context.py` | read; timing reproduction pending | All 227 lines read; source binding, caps and caches traced. |
| `app/web/assets/console.css` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `app/web/assets/console.js` | read; follow-through pending | Byte-identical to reviewed assets/console.js. |
| `app/web/assets/index-B9Da4QyI.js` | pending | |
| `app/web/assets/index-ut3zQWOW.css` | pending | |
| `app/web/index.html` | read; follow-through pending | Full source read; findings and evidence below. |
| `assets/console.css` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `assets/console.js` | read; follow-through pending | Full source read; findings and evidence below. |
| `assets/index-B9Da4QyI.js` | pending | |
| `assets/index-ut3zQWOW.css` | pending | |
| `docs/all-chain-ledger.md` | read; historical evidence scope checked | All975 lines read across continuation; no new live verification. |
| `docs/astra-audit.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/implementation-plan.md` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `docs/model-endpoint-target-investigation.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/production-verification.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/verified-abi-context.md` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `index.html` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `run.bat` | read; cross-module verification pending | Full file read in audit continuation. |
| `run.sh` | read; cross-module verification pending | Full file read in audit continuation. |
| `tests/browser_checks.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/fixtures/blockscout_eth_hedgey_raw_trace.json` | pending | |
| `tests/fixtures/blockscout_optimism_raw_trace.json` | pending | |
| `tests/fixtures/blockscout_pro_trace_samples.json` | pending | |
| `tests/fixtures/hedgey_verified_abi.json` | pending | |
| `tests/fixtures/hedgey_verified_trace.json` | pending | |
| `tests/frontend.test.cjs` | read; follow-through pending | Full source read; findings and evidence below. |
| `tests/run_frontend_offline.cjs` | read; follow-through pending | Full source read; findings and evidence below. |
| `tests/run_offline.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `tests/test_candidate_pipeline_transport.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/test_explorer_trace.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_function_wall_guard.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_inception_route.py` | read; follow-through pending | Full source read; verification scope below. |
| `tests/test_inception_server_config.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_itera_route.py` | read; follow-through pending | Full source read; verification scope below. |
| `tests/test_model_endpoint.py` | read; follow-through pending | Full source read; verification scope below. |
| `tests/test_packaging.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_pinned_pipeline.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/test_pipeline_guards.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_rpc_transport.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_server.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/test_trace_identity.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tests/test_verified_abi_context.py` | read; follow-through pending | Full source read; browser/test/provenance limitations below. |
| `tools/pipeline_pin.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `tools/probe_local_pipeline.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `tools/sync_static.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |

## pipeline: 893fe1a8067c2b2f6fdcbc0899afa4622db76ac0

| File | Status | Evidence / findings |
|---|---|---|
| `.env.example` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `.github/workflows/ci.yml` | read; follow-through pending | Full source read; evidence below. |
| `.gitignore` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `Dockerfile.benchmark` | read; follow-through pending | Full source read; evidence below. |
| `LICENSE` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `README.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `benchmark/DATASET_INTEGRITY.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `benchmark/README.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `benchmark/analyze_explainability_study.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/audit_localization_misses.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/benchmark_classification.csv` | pending | |
| `benchmark/benchmark_classification_fixed.csv` | pending | |
| `benchmark/build_candidate_exploit_expansion.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/build_honest_latex_tables.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/build_research_exploit_pool.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/calibrator_cv_metrics.json` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `benchmark/collect_benign_traces.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/collect_contract_benign_traces.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/collect_real_benign_traces.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/dataset_sources.json` | read; provenance boundary recorded | Complete manifest read; no independent label verification. |
| `benchmark/detailed_miss_analysis.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/evaluate_localization_with_resolution.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/export_research_features.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/fetch_selector_names.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/fix_csv.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/generate_pipeline_predictions.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/ground_truth/0x00c5a772a58b117f142b2cbc8721b80d145ef7a910043ad08439863d0e78e300.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x0237855c63eb85c5f437fba5267cc869a08c58a49501e3e5ebec9990bdd97565.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x04e16a79ff928db2fa88619cdd045cdfc7979a61d836c9c9e585b3d6f6d8bc31.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x06d7e7436414c658a33452d28400799f3637e83930dcec39b3bd065dabc6ef04.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x07e5568b71f1f4d9234d5925473c598865c5ee1800348c1c4b044c6f0223f308.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x09925028ce5d6a54801d04ff8f39e79af6c24289e84b301ddcdb6adfa51e901b.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x0b062361e16a2ea0942cc1b4462b6584208c8c864609ff73aaa640aaa2d92428.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x0eb8f8d148508e752d9643ccf49ac4cb0c21cbad346b5bbcf2d06974d31bd5c4.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x0fc5c0d41e5506fdb9434fab4815a4ff671afc834e47a533b3bed7182ece73b0.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x1106418384414ed56cd7cbb9fedc66a02d39b663d580abc618f2d387348354ab.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x1194e1d6085885ce054a7ff8cd3cd0c3fa308ec87e4ccde8dd0549842fef4f1b.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x12fe79f1de8aed0ba947cec4dce5d33368d649903cb45a5d3e915cc459e751fc.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x138daa4cbeaa3db42eefcec26e234fc2c89a4aa17d6b1870fc460b2856fd11a6.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x160c5950a01b88953648ba90ec0a29b0c5383e055d35a7835d905c53a3dda01e.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x19c04bc04ee8117abfdf0c9301787b12b27f3c5c13308b4f66711a8f0ecacc62.json` | read; incident provenance unverified | Full artifact read; no external adjudication or rescoring. |
| `benchmark/ground_truth/0x1a7ee0a7efc70ed7429edef069a1dd001fbff378748d91f17ab1876dc6d10392.json` | pending | |
| `benchmark/ground_truth/0x1ea0a2e88efceccb2dd93e6e5cb89e5421666caeefb1e6fc41b68168373da342.json` | pending | |
| `benchmark/ground_truth/0x1f1aba5bef04b7026ae3cb1cb77987071a8aff9592e785dd99860566ccad83d1.json` | pending | |
| `benchmark/ground_truth/0x1fe5a53405d00ce2f3e15b214c7486c69cbc5bf165cf9596e86f797f62e81914.json` | pending | |
| `benchmark/ground_truth/0x20ecd8310a2cc7f7774aa5a045c8a99ad84a8451d6650f24e0911e9f4355b13a.json` | pending | |
| `benchmark/ground_truth/0x21d8b164f0cb8beb1ed27d164ed986c3fc26b33655ce18226b05b9cfcf6cd93c.json` | pending | |
| `benchmark/ground_truth/0x23fcf9d4517f7cc39815b09b0a80c023ab2c8196c826c93b4100f2e26b701286.json` | pending | |
| `benchmark/ground_truth/0x24a68d2a4bbb02f398d3601acfd87b09f543d935fc24862c314aaf64c295acdb.json` | pending | |
| `benchmark/ground_truth/0x256979ae169abb7fbbbbc14188742f4b9debf48b48ad5b5207cadcc99ccb493b.json` | pending | |
| `benchmark/ground_truth/0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739.json` | pending | |
| `benchmark/ground_truth/0x26a83db7e28838dd9fee6fb7314ae58dcc6aee9a20bf224c386ff5e80f7e4cf2.json` | pending | |
| `benchmark/ground_truth/0x2881e839d4d562fad5356183e4f6a9d427ba6f475614ce8ef64dbfe557a4a2cc.json` | pending | |
| `benchmark/ground_truth/0x2a027c8b915c3737942f512fc5d26fd15752d0332353b3059de771a35a606c2d.json` | pending | |
| `benchmark/ground_truth/0x2b6d0af0dc513a15e325703405739057f9de6ef3f99934b957653b8a3fade4c6.json` | pending | |
| `benchmark/ground_truth/0x2e2d9f262dcaa4a6ccdb047092f837b0f65ae533b34332428674d3f36308ff83.json` | pending | |
| `benchmark/ground_truth/0x2e832f044b4a0a0b8d38166fe4d781ab330b05b9efa9e72a7a0895f1b984084b.json` | pending | |
| `benchmark/ground_truth/0x33479bcfbc792aa0f8103ab0d7a3784788b5b0e1467c81ffbed1b7682660b4fa.json` | pending | |
| `benchmark/ground_truth/0x35a73969f582872c25c96c48d8bb31c23eab8a49c19282c67509b96186734e60.json` | pending | |
| `benchmark/ground_truth/0x35ecf595864400696853c53edf3e3d60096639b6071cadea6076c9c6ceb921c1.json` | pending | |
| `benchmark/ground_truth/0x37acd17a80a5f95728459bfea85cb2e1f64b4c75cf4a4c8dcb61964e26860882.json` | pending | |
| `benchmark/ground_truth/0x3bba4fb6de00dd38df3ad68e51c19fe575a95a296e0632028f101c5199b6f714.json` | pending | |
| `benchmark/ground_truth/0x3c09c6306b67737227edc24c663462d870e7c2bf39e9ab66877a980c900dd5d5.json` | pending | |
| `benchmark/ground_truth/0x3d163bfbec5686d428a6d43e45e2626a220cc4fcfac7620c620b82c1f2537c78.json` | pending | |
| `benchmark/ground_truth/0x3ed75df83d907412af874b7998d911fdf990704da87c2b1a8cf95ca5d21504cf.json` | pending | |
| `benchmark/ground_truth/0x3f1973fe56de5ecd59a815d3b14741cf48385903b0ccfe248f7f10c2765061f7.json` | pending | |
| `benchmark/ground_truth/0x4019890fe5a5bd527cd3b9f7ee6d94e55b331709b703317860d028745e33a8ca.json` | pending | |
| `benchmark/ground_truth/0x44aad3b853866468161735496a5d9cc961ce5aa872924c5d78673076b1cd95aa.json` | pending | |
| `benchmark/ground_truth/0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882.json` | pending | |
| `benchmark/ground_truth/0x485e08dc2b6a4b3aeadcb89c3d18a37666dc7d9424961a2091d6b3696792f0f3.json` | pending | |
| `benchmark/ground_truth/0x48d22ea24c1ae707b8b17ca2a3ea81a1aee64a075d93e5bff81a7370e2cacea7.json` | pending | |
| `benchmark/ground_truth/0x491cf8b2a5753fdbf3096b42e0a16bc109b957dc112d6537b1ed306e483d0744.json` | pending | |
| `benchmark/ground_truth/0x4c684fb2618c29743531dec9253ede1b757bda0b323dc2f305e3b50ab1773da7.json` | pending | |
| `benchmark/ground_truth/0x4e5bb7e3f552f5ee6ee97db9a9fcf07287aae9a1974e24999690855741121aff.json` | pending | |
| `benchmark/ground_truth/0x4f4d6909a442b4d86f79a9044dcada6a128ddd9f62c26f410134a72d2fc31389.json` | pending | |
| `benchmark/ground_truth/0x57b589f631f8ff20e2a89a649c4ec2e35be72eaecf155fdfde981c0fec2be5ba.json` | pending | |
| `benchmark/ground_truth/0x597d11c05563611cb4ad4ed4c57ca53bbe3b7d3fefc37d1ef0724ad58904742b.json` | pending | |
| `benchmark/ground_truth/0x6200bf5c43c214caa1177c3676293442059b4f39eb5dbae6cfd4e6ad16305668.json` | pending | |
| `benchmark/ground_truth/0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d.json` | pending | |
| `benchmark/ground_truth/0x6bfd9e286e37061ed279e4f139fbc03c8bd707a2cdd15f7260549052cbba79b7.json` | pending | |
| `benchmark/ground_truth/0x6e6e556a5685980317cb2afdb628ed4a845b3cbd1c98bdaffd0561cb2c4790fa.json` | pending | |
| `benchmark/ground_truth/0x6fb7f8e9eb09d6ae17dbe82b2b42f46f64fb9c3197438b68ecf03e832d5fc791.json` | pending | |
| `benchmark/ground_truth/0x725f0d65340c859e0f64e72ca8260220c526c3e0ccde530004160809f6177940.json` | pending | |
| `benchmark/ground_truth/0x72a252277e30ea6a37d2dc9905c280f3bc389b87f72b81a59aa8f50baebd8eaa.json` | pending | |
| `benchmark/ground_truth/0x7604c7dd6e9bcdba8bac277f1f8e7c1e4c6bb57afd4ddf6a16f629e8495a0281.json` | pending | |
| `benchmark/ground_truth/0x7c5a909b45014e35ddb89697f6be38d08eff30e7c3d3d553033a6efc3b444fdd.json` | pending | |
| `benchmark/ground_truth/0x800a5b3178f680feebb81af69bd3dff791b886d4ce31615e601f2bb1f543bb2e.json` | pending | |
| `benchmark/ground_truth/0x873f7c77d5489c1990f701e9bb312c103c5ebcdcf0a472db726730814bfd55f3.json` | pending | |
| `benchmark/ground_truth/0x8a8145ab28b5d2a2e61d74c02c12350731f479b3175893de2014124f998bff32.json` | pending | |
| `benchmark/ground_truth/0x8c3f442fc6d640a6ff3ea0b12be64f1d4609ea94edd2966f42c01cd9bdcf04b5.json` | pending | |
| `benchmark/ground_truth/0x8e1b0ab098c4cc5f632e00b0842b5f825bbd15ded796d4a59880bb724f6c5372.json` | pending | |
| `benchmark/ground_truth/0x90b468608fbcc7faef46502b198471311baca3baab49242a4a85b73d4924379b.json` | pending | |
| `benchmark/ground_truth/0x90fb0c9976361f537330a5617a404045ffb3fef5972cf67b531386014eeae7a9.json` | pending | |
| `benchmark/ground_truth/0x958236266991bc3fe3b77feaacea120f172c0708ad01c7a715b255f218f9313c.json` | pending | |
| `benchmark/ground_truth/0x95c1604789c93f41940a7fd9eca11276975a9a65d250b89a247736287dbd2b7e.json` | pending | |
| `benchmark/ground_truth/0x995e880635f4a7462a420a58527023f946710167ea4c6c093d7d193062a33b01.json` | pending | |
| `benchmark/ground_truth/0x998f1da472d927e74405b0aa1bbf5c1dbc50d74b39977bed3307ea2ada1f1d3f.json` | pending | |
| `benchmark/ground_truth/0x9f14d093a2349de08f02fc0fb018dadb449351d0cdb7d0738ff69cc6fef5f299.json` | pending | |
| `benchmark/ground_truth/0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57.json` | pending | |
| `benchmark/ground_truth/0xa4e650772f6e6b7ecc0964fe4c3854850669d1467570a2fa2b6edfa0f112c4b7.json` | pending | |
| `benchmark/ground_truth/0xa6f63fcb6bec8818864d96a5b1bb19e8bd85ee37b2cc916412e720988440b2aa.json` | pending | |
| `benchmark/ground_truth/0xa992b28ecf2eed778d20d5200946ea341b950be0c3d78b1f2237a4d8d795de95.json` | pending | |
| `benchmark/ground_truth/0xac7292e7d0ec8ebe1c94203d190874b2aab30592327b6cc875d00f18de6f3133.json` | pending | |
| `benchmark/ground_truth/0xad818ec910def08c70ac519ab0fffa084b4178014a91cd8aa2f882d972a511c1.json` | pending | |
| `benchmark/ground_truth/0xaee0f8d1235584a3212f233b655f87b89f22f1d4890782447c4ef742b37af58d.json` | pending | |
| `benchmark/ground_truth/0xaf46a42fe1ed7193b25c523723dc047c7500e50a00ecb7bbb822d665adb3e1f3.json` | pending | |
| `benchmark/ground_truth/0xb072f2e88058c147d8ff643694b43a42e36525b7173ce1daf76e6c06170b0e77.json` | pending | |
| `benchmark/ground_truth/0xb36486f032a450782d5d2fac118ea90a6d3b08cac3409d949c59b43bcd6dbb8f.json` | pending | |
| `benchmark/ground_truth/0xb61413c495fdad6114a7aa863a00b2e3c28945979a10885b12b30316ea9f072c.json` | pending | |
| `benchmark/ground_truth/0xbd72bccec6dd824f8cac5d9a3a2364794c9272d7f7348d074b580e3c6e44312e.json` | pending | |
| `benchmark/ground_truth/0xbea605b238c85aabe5edc636219155d8c4879d6b05c48091cf1f7286bd4702ba.json` | pending | |
| `benchmark/ground_truth/0xc0be8c3792a5b1ba7d653dc681ff611a5b79a75fe51c359cf1aac633e9441574.json` | pending | |
| `benchmark/ground_truth/0xc18ec2eb7d41638d9982281e766945d0428aaeda6211b4ccb6626ea7cff31f4a.json` | pending | |
| `benchmark/ground_truth/0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d.json` | pending | |
| `benchmark/ground_truth/0xc42fc0e22a0f60cc299be80eb0c0ddce83c21c14a3dddd8430628011c3e20d6b.json` | pending | |
| `benchmark/ground_truth/0xc9b2cbc1437bbcd8c328b6d7cdbdae33d7d2a9ef07eca18b4922aac0430991e7.json` | pending | |
| `benchmark/ground_truth/0xcbe521aea28911fe9983030748028e12541e347b8b6b974d026fa5065c22f0cf.json` | pending | |
| `benchmark/ground_truth/0xcdd93e37ba2991ce02d8ca07bf6563bf5cd5ae801cbbce3dd0babb22e30b2dbe.json` | pending | |
| `benchmark/ground_truth/0xcf834aff4de9992f5da9c443600dad9c6277a8a00de5007842fece51564992db.json` | pending | |
| `benchmark/ground_truth/0xd493c73397952049644c531309df3dd4134bf3db1e64eb6f0b68b016ee0bffde.json` | pending | |
| `benchmark/ground_truth/0xd4fafa1261f6e4f9c8543228a67caf9d02811e4ad3058a2714323964a8db61f6.json` | pending | |
| `benchmark/ground_truth/0xd5b4d68432cbbd912130bbb5b93399031ddbb400d8f723c78050574de7533106.json` | pending | |
| `benchmark/ground_truth/0xd9156f507c701a09d3312e1987383c7c882df50b3127e1adfd74d74052642114.json` | pending | |
| `benchmark/ground_truth/0xd927843e30c6b2bf43103d83bca6abead648eac3cad0d05b1b0eb84cd87de9b6.json` | pending | |
| `benchmark/ground_truth/0xd9b3e229acc755881890394cc76fde0d7b83b1abd4d046b0f69c1fd9fd495ff6.json` | pending | |
| `benchmark/ground_truth/0xda8f6a4bed7e5689a343d111632d37480c0316f1d20b732803c4bd482823e284.json` | pending | |
| `benchmark/ground_truth/0xdaccbc437cb07427394704fbcc8366589ffccf974ec6524f3483844b043f31d5.json` | pending | |
| `benchmark/ground_truth/0xdd0636e2598f4d7b74f364fedb38f334365fd956747a04a6dd597444af0bc1c0.json` | pending | |
| `benchmark/ground_truth/0xdf6252854362c3e96fd086d9c3a5397c303d265649aee0b023176bb49cf00d4b.json` | pending | |
| `benchmark/ground_truth/0xe4db1550e3aa78a05e93bfd8fbe21b6eba5cce50dc06688949ab479ebed18048.json` | pending | |
| `benchmark/ground_truth/0xe8277ef6ba8611bd12dc5a6e7ca4b984423bc0b3828159f83b466fdcf4fe054f.json` | pending | |
| `benchmark/ground_truth/0xeaef2831d4d6bca04e4e9035613be637ae3b0034977673c1c2f10903926f29c0.json` | pending | |
| `benchmark/ground_truth/0xeb8c3bebed11e2e4fcd30cbfc2fb3c55c4ca166003c7f7d319e78eaab9747098.json` | pending | |
| `benchmark/ground_truth/0xf0a13b445674094c455de9e947a25bade75cac9f5176695fca418898ea25742f.json` | pending | |
| `benchmark/ground_truth/0xf1818f62c635e5c80ef16b7857da812c74ce330ebed46682b4d173bffe84c666.json` | pending | |
| `benchmark/ground_truth/0xf4a3d0e01bbca6c114954d4a49503fc94dfdbc864bded5530b51a207640d86b5.json` | pending | |
| `benchmark/ground_truth/0xf72f1d10fc6923f87279ce6c0aef46e372c6652a696f280b0465a301a92f2e26.json` | pending | |
| `benchmark/ground_truth/0xfc872bf5ca8f04b18b82041ec563e4abf2e31e1fc27d1ea5dee39bc8a79d2d06.json` | pending | |
| `benchmark/ground_truth/0xfe8bc757d87e97a5471378c90d390df47e1b29bb9fca918b94acd8ecfaadc598.json` | pending | |
| `benchmark/ground_truth/0xfeedbf51b4e2338e38171f6e19501327294ab1907ab44cfd2d7e7336c975ace7.json` | pending | |
| `benchmark/honest_eval/__init__.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/honest_eval/features.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/honest_eval/leakage_guard.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/honest_eval/localization.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/honest_eval/metrics.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/import_defihacklabs_github.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/import_defillama_hacks.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/import_hf_ethereum_activity.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/import_public_incidents.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/import_rugpull_contracts.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/imported/benign_traces.csv` | pending | |
| `benchmark/imported/contract_benign_traces.csv` | pending | |
| `benchmark/imported/defihacklabs_candidate_expansion.csv` | pending | |
| `benchmark/imported/defihacklabs_candidate_expansion_summary.json` | pending | |
| `benchmark/imported/defihacklabs_github_candidates.csv` | pending | |
| `benchmark/imported/defihacklabs_github_candidates_summary.json` | read; provenance boundary recorded | Complete manifest read; no independent label verification. |
| `benchmark/imported/defihacklabs_incidents.full.csv` | pending | |
| `benchmark/imported/defihacklabs_validation_manifest.full.csv` | pending | |
| `benchmark/imported/defihacklabs_validation_summary.full.json` | read; provenance boundary recorded | Complete manifest read; no independent label verification. |
| `benchmark/imported/defillama_hacks.full.csv` | pending | |
| `benchmark/imported/hf_ethereum_benign_transactions.csv` | pending | |
| `benchmark/imported/hf_ethereum_benign_transactions_summary.json` | read; provenance boundary recorded | Complete manifest read; no independent label verification. |
| `benchmark/imported/hf_ethereum_benign_transactions_validation.json` | read; provenance boundary recorded | Complete manifest read; no independent label verification. |
| `benchmark/imported/rugpull_contract_incidents.csv` | pending | |
| `benchmark/imported/rugpull_contract_incidents_summary.json` | pending | |
| `benchmark/ingest_external_baselines.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/prepare_research_dataset.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/quarantine_invalid_verified_rows.csv` | pending | |
| `benchmark/research_exploit_pool.csv` | pending | |
| `benchmark/research_exploit_pool_summary.json` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `benchmark/research_readiness_report.json` | pending | |
| `benchmark/research_readiness_report.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `benchmark/retrain_calibrator.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/retrain_calibrator_kfold.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/run_adversarial_eval.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/run_eval.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/run_honest_experiments.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/run_localization_eval.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/run_research_experiments.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/sync_results.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/validate_benign_dataset.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/validate_dataset.py` | read; follow-through pending | Full source read; evidence below. |
| `benchmark/validate_imported_incidents.py` | read; follow-through pending | Full source read; evidence below. |
| `data/models/calibrator.json` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `data/models/calibrator_cv_metrics.json` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `data/models/calibrator_metrics.json` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `data/models/selector_cache.json` | pending | |
| `docs/DATASET_REGISTRY.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/ABLATION_PROTOCOL.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/BASELINE_MATRIX.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/BENIGN_DATA_ACQUISITION.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/ERROR_TAXONOMY.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/HUMAN_EXPLAINABILITY_STUDY.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/NOVEL_ALGORITHM.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/REPRODUCIBILITY_CHECKLIST.md` | read; follow-through pending | Full source read; evidence below. |
| `docs/research/human_study_response_template.csv` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/__main__.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/core/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/core/auto_model_selector.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/core/base_agent.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/core/confidence_scorer.py` | read; findings / follow-through pending | Full file read; numeric normalization and empty-pattern reproduction confirmed. |
| `faultseeker/core/config.py` | read; cross-module verification pending | Full file read in audit continuation. |
| `faultseeker/core/cross_chain_runner.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/core/human_interface.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/core/llm_router.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/core/pipeline.py` | read; cross-module verification pending | Full file read in audit continuation. |
| `faultseeker/data_collection/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/data_collection/contract_downloader.py` | read; follow-through pending | Full file read; findings recorded below. |
| `faultseeker/data_collection/contract_info_collector.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/data_collection/trace_parser.py` | read; consumer review pending | All 164 lines read at candidate893fe1a. |
| `faultseeker/data_collection/trace_visualizer.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/data_collection/txn_info_collector.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/data_collection/txn_replayer.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/data_collection/txn_sequencer.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/forensics/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/forensics/adaptive_controller.py` | read; cross-module verification pending | Full file read in audit continuation. |
| `faultseeker/forensics/address_classifier.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/forensics/fund_flow_analyzer.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/forensics/interaction_graph.py` | read; findings / follow-through pending | Full file read; bounded graph growth experiment completed. |
| `faultseeker/forensics/orchestrator.py` | read; findings / follow-through pending | Full file read; signal, graph and calibration dataflow traced. |
| `faultseeker/forensics/result.py` | read; cross-module verification pending | Full file read in audit continuation. |
| `faultseeker/forensics/rule_classifier.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/forensics/signal_extractor.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/forensics/trace_analyzer.py` | read; consumer review pending | All 227 lines read at candidate893fe1a. |
| `faultseeker/function_analysis/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/function_analysis/function_analyzer.py` | read; findings / follow-through pending | Full file read across contiguous batches; source target substitution reproduced; exception and finalization paths reviewed. |
| `faultseeker/function_analysis/function_ranker.py` | read; follow-through pending | Full file read; findings recorded below. |
| `faultseeker/main.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/prompts/__init__.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/forensics/__init__.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/forensics/address_classification_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/forensics/fund_flow_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/forensics/trace_analysis_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/function_analysis/__init__.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/function_analysis/local_task_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/function_analysis/orchestration_session_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/function_analysis/task_coordinator_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/function_analysis/vulnerability_analysis_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/function_analysis/worker_prompts.py` | read; follow-through pending | Full source read; evidence below. |
| `faultseeker/prompts/local_model_prompts.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/research/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/research/ablation.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/adversarial.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/calibration.py` | read; findings / follow-through pending | Full file read; malformed vector acceptance reproduced; callers inspected. |
| `faultseeker/research/chain_profiles.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/cost_tracker.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/failure_aware_localization.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/mempool.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/remediation.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/statistics.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/research/temporal.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/utils/agent.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/utils/chunk_splitter.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/utils/explorer_provider.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/utils/rpc_provider.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/utils/solidityParser/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/utils/solidityParser/antlrGenerated/SolidityLexer.py` | pending | |
| `faultseeker/utils/solidityParser/antlrGenerated/SolidityListener.py` | complete structural behavior review | All190 callbacks verified pass-only; imports/class/delete reviewed; no grammar correctness claim. |
| `faultseeker/utils/solidityParser/antlrGenerated/SolidityParser.py` | pending | |
| `faultseeker/utils/solidityParser/antlrGenerated/__init__.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `faultseeker/utils/solidityParser/constantTokenId.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/utils/solidityParser/constraintExtractor.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/utils/solidityParser/hash_parser.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `faultseeker/utils/solidityParser/loc_parser.py` | read; follow-through pending | Full read; caller/tests coverage and observations below. |
| `faultseeker/utils/utils.py` | read; follow-through pending | Full source read; findings and evidence below. |
| `foundry.toml` | read; follow-through pending | Full source read; evidence below. |
| `generate_charts.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `paper/WORD_COUNT.txt` | read; artifact consistency checked | Full read; mismatches recorded below. |
| `paper/blockchain_exploit_forensics_survey_ieee.tex` | pending | |
| `pyproject.toml` | read; follow-through pending | Full source read; evidence below. |
| `reports/SYNTHETIC_DO_NOT_CITE/README.md` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `reports/SYNTHETIC_DO_NOT_CITE/ablation_results.csv` | pending | |
| `reports/SYNTHETIC_DO_NOT_CITE/adversarial_robustness.csv` | pending | |
| `reports/SYNTHETIC_DO_NOT_CITE/baseline_comparison.csv` | pending | |
| `reports/SYNTHETIC_DO_NOT_CITE/research_tables.tex` | read; artifact consistency checked | Full read; mismatches recorded below. |
| `reports/SYNTHETIC_DO_NOT_CITE/summary.json` | pending | |
| `reports/honest_results/adversarial_robustness.csv` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `reports/honest_results/baseline_comparison.csv` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `reports/honest_results/honest_research_tables.tex` | read; artifact consistency checked | Full read; mismatches recorded below. |
| `reports/honest_results/localization_metrics.json` | pending | |
| `reports/honest_results/reliability_diagram.csv` | pending | |
| `reports/honest_results/status.json` | pending | |
| `reports/research_results/ablation_results.csv` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `reports/research_results/adversarial_robustness.csv` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `reports/research_results/baseline_comparison.csv` | read; report provenance limitations recorded | Full artifact read; no independent evaluation rerun. |
| `reports/research_results/reentrancy_metrics.json` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `reports/research_results/reproducibility_manifest.json` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `reports/research_results/research_tables.tex` | read; artifact consistency checked | Full read; mismatches recorded below. |
| `reports/research_results/runtime_cost.json` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `reports/research_results/summary.json` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `requirements.txt` | read; follow-through pending | Full source read; evidence below. |
| `run_tests_nopytest.py` | read; follow-through pending | Full source read; findings and limitations below. |
| `setup.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/CALIBRATION_REGRESSION.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `tests/COMBINED_VALIDATION.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `tests/DEPTH_REGRESSION.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `tests/PARITY_CREATION_REGRESSION.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `tests/RPC_USER_AGENT_REGRESSION.md` | read; evidence scope recorded | Full read; claims checked against implementation where available. |
| `tests/__init__.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/fixtures/hedgey_setup_descendants.json` | pending | |
| `tests/run_offline_address_context.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/run_offline_calibration.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/run_offline_depth.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/run_offline_descendants.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/run_offline_parity.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/run_offline_rpc.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_adaptive_controller.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_calibrated_reporting.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_combined_pipeline_integrity.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_confidence_scorer.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_cost_tracker_ablation.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_deep_application_path.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/test_deep_rpc_normalization.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_deep_trace_flattening.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_deep_trace_objects.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_external_baseline_and_human_study.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_function_analyzer_provider_routing.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_function_target_memo.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_honest_eval.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_llm_router.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_llm_router_ablation.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_orchestrator_research_metrics.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_orchestrator_wiring.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_parity_creation_normalization.py` | read; follow-through pending | Full source read; evidence below. |
| `tests/test_pipeline_parse.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_public_incident_import.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_reentrancy_eval_integration.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_reentrancy_state_signals.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_registered_cloud_policy.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_research_experiment_suite.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_research_modules.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_research_system_surfaces.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_research_tooling_robustness.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_rpc_user_agent.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_target_address_context.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `tests/test_target_descendant_counts.py` | read; coverage limitations recorded | Full source read; not proof of live forensic correctness. |
| `verify_paper_validity.py` | read; follow-through pending | Full source read; findings and limitations below. |

## Execution-path review order

1. Input, gate, RPC destination and credential boundaries.
2. Model routing, preflight, retries, budgets and cancellation.
3. Trace identity, source/ABI provenance and caches.
4. Signal extraction, rule classification and target ranking.
5. Function/transaction workers, prompt content and completion tracking.
6. Scoring, calibration, evidence consistency and report integrity.
7. Storage, history, streaming, frontend rendering and deployment configuration.

## Resume point

Resume app/model_routes.py, app/model_endpoint.py and app/pipeline_guards.py; trace diagnostic and report-adapter findings through callers. Prior findings remain leads until checked against these revisions. Review all listed files; explicitly classify non-code/generated artifacts rather than silently excluding them.

## Audit observations: server lines 1-524

- Confirmed behavior, decision to assess: server.py:461-462 and 515-520 use a deterministic HMAC of the shared gate password as the bearer cookie. The seven-day max_age is only browser expiry; the server checks equality without issuance/expiry time. A copied valid cookie remains accepted until the gate password changes. Suggested fix: signed expiry-bearing session cookie, preserving shared admitted-user history. Do not claim password disclosure or public gate bypass.
- Existing limitation revalidated: server.py:185-190 checks a restoration scheduling deadline between reads; urllib timeout is not a total streaming deadline. Need isolated slow-stream reproduction and deployment impact assessment before classifying severity.
- History index retains 200 entries (54-58), while result/event-file retention is not established by this section. Trace cleanup callers before alleging disk growth.
- Event-file cap (267-271) checks existing size before appending an event. Per-event size bounds must be traced through producers before deciding impact.
- No whole-file completion claimed. No external requests or model calls made in this audit slice.

## Server read-through completed (1491 lines; dependency review pending)

- Confirmed adapter inconsistency: server.py:1252-1253 returns existing transaction/classification unchanged before partial-status verdict normalization at 1291/1321. Isolated execution of the actual AST function with analysis_status=partial and rule_verdict=EXPLOIT returns EXPLOIT. Impact through each UI/API caller remains to be checked; do not claim the current frontend displays a successful verdict yet. Suggested fix: normalize status for both input shapes.
- Confirmed interface exposure: GET /api/llm-selftest accepts keys as a query parameter (586-610). This places caller credentials in request URLs, outside response redaction. Log capture reproduction pending; do not claim actual credentials leaked. Suggested fix: POST body for supplied keys, reject credential query parameters, update diagnostic callers.
- Confirmed retention behavior: completed result files are retained indefinitely (1013-1016 explicitly only prune stream buffers); index retains 200. Production disk impact depends on report sizes/run frequency. Replays bypass that memory-buffer pruning branch; repeated replay memory-growth reproduction pending.
- Worker queue termination, cancellation finalization and report storage paths read in full. Cleanup on unexpected parent exceptions needs isolated lifecycle coverage. No security fix or complete cross-module audit claimed from read-through alone.
- Executed isolated adapter reproduction only; no network, credentials or model calls. Project runtime files unchanged in this audit slice. Kluster tools unavailable.

## Model route and transport read-through

- Confirmed response-validation gap: model_endpoint.py:348-375 rejects a list of known unfinished finish_reason values but accepts a missing finish_reason when content is nonempty. Dummy local client executing actual ModelEndpointSession.call returned a completion with finish_reason=None and analysis ok=1. No HTTP or credentials used. Suggested fix: explicitly require supported terminal completion semantics, with provider compatibility tests; do not promote unknown/missing finish reasons to success.
- Diagnostic differs from shared transport: server.py:630-637 passes eight output tokens through adapt_request with its default analysis phase, so Mercury uses low reasoning instead of preflight instant. It marks ok on any returned choice without shared finish/content validation. Thus diagnostic success does not prove model readiness. Need mocked endpoint route regression.
- Preflight retries are bounded by deadline/shared elapsed budget but bypass retries_left decrement (model_endpoint.py:501-508). This is current policy, not claimed an endless loop. Assess against original shared retry-count requirement and record explicit decision/fix.
- Full model_routes.py (117 lines) and model_endpoint.py (587 lines) read. Remaining caller/test review: pipeline_guards.py, transport tests, client cleanup and concurrency edge reproductions. No forensic correctness claim.

## Pipeline integration and verified source read-through

- Confirmed evidence-loss behavior: pipeline_guards.py:107-108 returns an empty string when every interface lookup is unverified, discarding unverified counts and the explicit instruction against inferred selector semantics. worker setup at 427 likewise supplies metadata only when facts are nonempty. Provider/source failure can therefore leave the model with no explicit interface-coverage warning. Reproduce through real prompt construction before fixing.
- Confirmed scope: verified source is only the main compilation unit (verified_abi_context.py:169-185); imported contracts/base-class function bodies are omitted. This is explicitly labeled in report metadata, but worker source entries contain scope without the limitations list. Trace prompt consumers to determine whether missing dependencies are communicated adequately.
- Source phase deadline starts at the first source request and expires after 30 seconds of wall time (115-121), including model processing between sequential functions. A later contract can be denied source even if earlier source I/O was short. This is a bounded policy, but its fit with sequential multi-minute analysis needs a regression and design assessment; do not silently increase limits.
- Historical bytecode is bound by chain ID and block number, not block hash; block-end scope is labeled. Reorg/context fidelity requires reviewing RPC/trace consumers before stronger claims.
- Completion requires observed model and FunctionAnalyzer.run activity, but annotate_result does not require a nonempty wall-ledger record set. Trace legitimate empty-work paths before deciding whether this is a false-success defect.
- All 649 pipeline_guards.py and 227 verified_abi_context.py lines read. Resume trace_identity.py, explorer_trace.py and rpc_transport.py, then actual pipeline consumers. No new model/API calls, no production code edits in this slice.

## Trace and RPC transport audit

- Confirmed data loss: trace_identity.py:9-19 canonical_to_legacy drops frame error (and output) fields. explorer_trace.py:225-230 restores errors onto canonical nodes, but pipeline_guards.py:314 converts those nodes again for analysis. Isolated actual conversion of an error-bearing frame returned no error key. Trace downstream state-change/profit inference before assigning final impact; provenance counts alone do not retain error attribution in each analysis frame.
- Confirmed validation gap: trace_identity.py:35-49 compares missing values as empty strings. Actual validate_trace_root accepted a transaction/root pair with both sender and calldata absent. Standard valid RPC responses include these fields, but malformed upstream data does not fail closed. Suggested fix: validate required transaction/root fields and formats before comparison.
- Root value is not cross-checked against transaction value. Block identity cross-check uses transaction metadata but needs cached-trace block comparison review. Neither proves an observed real-world mismatch yet.
- RPC transport validates all DNS answers, pins numeric connections, keeps TLS hostname verification and rejects redirects. Timeout is per socket operation and per attempted address, not total wall time; DNS has no explicit deadline. Bounded-worker kill remains a separate mechanism. No SSRF bypass claimed.
- Explorer callTracer conversion is recursive at lines 107-118; deep-tree capability depends on runtime recursion setup. Existing pipeline depth fixes do not automatically prove this independent adapter safe. Reproduction pending.
- Read complete trace_identity.py (97), rpc_transport.py (169), explorer_trace.py (237). Offline reproductions only; no external traffic. Resume actual pipeline trace parser/analyzer and data consumers, then remaining console modules/tests/configuration.

## Pipeline trace parser/analyzer

- Read all trace_parser.py (164) and forensics/trace_analyzer.py (227). TraceNode has no error/output fields, so round-trip also loses them. Analyzer copies remaining frame fields into flattened records, but separately retains canonical_trace in its output (214); impact must distinguish consumers of canonical and flattened trees.
- Confirmed structural interaction: analyzer.py:160-161 categorizes raw selectors as name_in_hash. Isolated execution of the actual _flatten_trace_frame method placed standard transfer selector 0xa9059cbb in that category. SignalExtractor previously inspected at 697-704 treats a nonempty name_in_hash list as closed_source_state_change. Thus selector-preserving console input can trigger this exploit heuristic without source evidence. Next: review all signal consumers and classifier in full, then reproduce the combined path without network.
- Text parser silently skips frames beyond depth_limit=1000 (103-104). Console canonical replacement may supersede this tree, so do not claim current structured path truncates at this point.
- Repeated-pattern search compares slices for multiple pattern lengths and positions; possible high CPU on wide traces needs measurement before assigning a performance finding.
- No code fixes or external calls in this slice. Resume signal_extractor.py and rule_classifier.py, then orchestrator and function ranking.

## Offline classifier reproduction (current candidate 893fe1a)

Confirmed, high correctness impact; not yet fixed. Imported the actual SignalExtractor and rule_classifier from the candidate checkout; socket.socket replaced with a raising function before imports, python -B, no model calls. Each case ran the complete SignalExtractor.run() then classify(), with empty txn_seq and a nonexistent audit cache hash:

| Input tx_analysis | Actual result |
|---|---|
| function_calls_to_expand_loc.name_in_hash=[0], no trace | EXPLOIT, 0.85, closed_source_access_control |
| One flatten_trace frame: function=implementation, call_type=delegatecall, dummy address | EXPLOIT, 0.80, access_control_bypass |
| One flatten_trace frame: function=pause, call_type=call, dummy address | EXPLOIT, 0.80, access_control_bypass |
| Empty control | UNCERTAIN, 0.40, no_signals_llm_required |

Evidence: signal_extractor.py:699-704 promotes decoding metadata to closed_source_state_change; :738 and :772-779 promote ordinary call patterns to bypass. rule_classifier.py:79-81 turns the first flag into a high-confidence exploit; generic bypass rule similarly returns EXPLOIT. orchestrator.py:235-240 records classification and :289-292 passes it to results. These inputs contain no authorization, unauthorized state change, or exploit evidence. Suggested fix: preserve observations separately from proven vulnerabilities; missing decoding and ordinary proxy/privileged calls must not establish exploit or access-control failure. Review remaining heuristic rules and downstream prompts before implementation. This is synthetic local negative-case evidence, not a verified historical trace or causal proof of the Hedgey model error.

Rule classifier read in full. Signal extractor bulk read was truncated; do not mark it fully reviewed. Resume with missing middle sections, orchestrator and downstream prompt/scoring consumers. No production code changed or new suite run in this audit block. Kluster unavailable (tool inventory contains no Kluster tools).

## Downstream verdict and numeric-evidence audit

Full orchestrator.py read. Signal extractor middle lines 271-706 read without truncation; remaining sections previously visible, full-file completion still requires coverage reconciliation. Function analyzer inspected at 289-335 and 761-880 only.

Confirmed high correctness-impact findings (not fixed):
- function_analysis/function_analyzer.py:787-794 seeds cheatsheet from rule EXPLOIT; :324 explicitly tells the organization model these entries have been confirmed vulnerable. This establishes prompt contamination by unsupported deterministic assertions, but does not independently establish causation for a particular historical model output. Fix should retain observations and require independent evidence, not suppress all context.
- signal_extractor.py price detector assigns price_delta_ratio=0.20 from two read/write sequences, without reserve values. Actual complete extractor.run -> classify offline reproduction with flatten_trace function names getreserves, swap, getreserves, swap, getreserves and no other evidence returned EXPLOIT 0.83 price_manipulation, price_delta_ratio 0.2. This is an invented quantitative measurement, not an observed price delta.
- Flash detector treats maximum gross call value as flash_profit_eth. Same offline path with a single flashloan frame value=2000000000000000000 returned EXPLOIT 0.88 flash_loan_profit, flash_profit_eth=2.0, profit_extraction_eth=2.0. No repayment, recipient, net balance, or profit evidence supplied. Preserve gross transfer amounts separately; missing profit must remain unknown.
- orchestrator.py assigns signals.raw.call_depth_max from graph_reasoning.node_count. interaction_graph.py:66 defines node_count as graph.number_of_nodes(), not execution depth. This feeds calibration call_depth. Static cross-module mismatch confirmed; isolated integration reproduction pending.

Reproduction environment: candidate893fe1a, python -B, socket.socket replaced with raising function before imports, actual SignalExtractor/ classifier, nonexistent cache identifier, no external calls. Two cases executed, both reproduced defects; these are not passing regression tests or chain verification. Production code unchanged. Next resume: function analyzer full file, confidence_scorer and calibration consumers, then implement coherent evidence semantics with regressions after audit coverage.

## Scoring, graph and function-analysis audit continuation

Confirmed findings, not fixed:

| Severity | Location | Evidence and impact | Suggested correction |
|---|---|---|---|
| High correctness | core/confidence_scorer.py:303-323 | Actual method: confidence_score=['1%'] -> 1.0; ['NaN'] -> 1.0; [0.01] -> 0.01. Invalid/low confidence is inflated into maximum confidence and affects final score/calibration. | Parse percent explicitly; reject nonfinite inputs before clamping; preserve missing/invalid status. |
| Medium correctness | core/confidence_scorer.py:211-219 | Actual method: repeated_patterns={} -> 0.0, but actual TraceAnalyzer schema {'keys':[], 'keys_function_only':[]} -> 0.3. Iterating dict keys also misses function names inside pattern values. Pipeline.py:216 passes this schema unchanged. | Normalize actual populated patterns and inspect their contents; test production schema. |
| High provenance | function_analysis/function_analyzer.py:225-253 | AST-extracted actual _retrieve_additional_info requested foo at dummy address 0x111... but fetched foo at 0x222... when adjacent summary keys share the name. No proxy relationship checked. | Keep requested address; follow implementation only with verified delegation/proxy provenance, reported explicitly. |
| Medium correctness | core/pipeline.py:250 versus forensics/orchestrator.py:217 | Final scoring reads signals.call_depth (default0); orchestrator writes call_depth_max using graph node count. Separate Stage1 calibration reads the latter. Both semantics/key mismatch. | Define one measured trace-depth feature and use consistently in training/inference; do not retrain frozen evaluation. |
| Medium validation | research/calibration.py:133-140,163 | Actual from_dict accepts trained model feature_names=[x,y], weights=[1], means/scales length2; predict returns0.7310585786300049 for x=1,y=1000, silently ignoring y through zip. | Validate matching vector lengths, finite values, positive scales, explicit trained state and supported schema before use. |

Confirmed behavior requiring policy review: function_analyzer.py:500-521 finalization keeps only maximum-depth findings. Actual extracted method with root depth1/confidence0.95 and child depth3/confidence0.1 returned only child. Evidence strength and ranked_result do not enter this filter. This proves exclusion, not that either synthetic finding is a real vulnerability. Review ranking contract before changing.

Resource risk: interaction_graph.py:60 materializes all simple cycles in address-collapsed graph. Bounded actual metrics() experiments: complete directed graphs of 6/7/8 nodes (30/42/56 edges) produced409/2365/16064 cycles in approximately0.000/0.016/0.046 seconds. Confirms rapid output growth; no production timeout or exploit demonstrated. Graph derives edges from transaction trace, so bounded cycle detection/counting should replace unbounded materialization while honestly reporting truncation. Do not present synthetic graph as historical transaction evidence.

Other follow-through: core/pipeline.py:221 omits contract_info from scorer.score_all, leaving code-availability component without actual source context. FunctionAnalyzer catches and silently drops malformed finding entries at347 and task exceptions at450/754; console guards must be traced before claiming these failures escape partial-state detection. Source retrieval rejects one-line functions at466; downstream source patch may supersede it. Optional trained-state check differs between Stage1 and Stage3; verify actual loaded model provenance before asserting probabilities reliable.

Executed local reproductions: scoring4 confidence cases and2 pattern cases; malformed calibrator1 case; graph3 bounded sizes; source address substitution1; finalization1. No model/RPC/network calls. Initial package-import attempt failed because replacing socket.socket with a function breaks ssl class initialization; corrected harness uses blocked socket subclass and direct importlib loading of actual modules. These isolated checks are not end-to-end integration tests. No suite rerun because production code unchanged. Kluster unavailable in tool inventory; no Kluster verification claimed.

Coverage next: full core/pipeline.py and forensics/result.py, function_ranker, contract_downloader, console guard interactions with findings above; then remaining files in inventory. Audit remains incomplete.

## Ranker and downloader continuation

Confirmed ranker defect: function_ranker.py repeated-pattern deduplication constructs its key from filtered entries only after requiring there are zero filtered entries. Every eligible pattern therefore has empty-string key. Actual FunctionRanker.rank with two distinct synthetic repeated patterns alpha and beta (each repeats=4) retained only alpha. No network or model calls; synthetic negative-case reproduction, not historical trace. Impact: subsequent distinct repeated patterns silently omitted from analysis. Fix should use ordered function/address identity of retained pattern and avoid mutating input.

Downloader review hypotheses pending console-path verification: single-file ContractName becomes a filename without path containment validation; shared output_dir ./temp2 and unconditional ./Implementation deletion can affect unrelated work/concurrent calls; failed download can parse stale files into a different contract cache; source cache identity includes address/chain but not historical bytecode/block; multi-file names flattened with underscores can collide. These are code observations, not proven remotely exploitable vulnerabilities. Console replaces downloader behavior in pipeline_guards, so establish effective path before severity/impact claims.

Next resume: console guard replacement versus downloader, full pipeline/result consumers, remaining inventory. Audit incomplete; no production fixes or deployment.

## Pipeline/report/config and launch-file review

Full reads completed for pipeline.py, result.py, config.py, adaptive_controller.py and console Dockerfile, .dockerignore, app requirements, run.sh/run.bat. Findings requiring follow-through: pipeline link parser uses substrings anywhere in input instead of explorer hostname; config max_functions_to_analyze/task_tree_max_depth not consumed by pipeline; HITL post-forensics modify records but does not apply modifications and abort handling needs human_interface trace; findings confirmations match function name without contract identity. Result.to_summary top_suspicious_functions returns category keys rather than actual functions. Adaptive tree expansion supplies integer depth when missing, while ranker/analyzer expect index paths; actual canonical/legacy paths must be tested before impact claim. Docker uses mutable stable Foundry archive without digest verification and partly unpinned dependencies; no downloads/builds performed. Windows launcher continues after dependency install failure; Linux cp -n under set -e needs platform-specific behavior verification.

Correction to downloader scope assumption: pipeline_guards.py:367 replaces FunctionAnalyzer._retrieve_source_code, not ContractDownloader.run; FunctionAnalyzer.run still initializes ContractDownloader before reviews. Therefore source filesystem path risks are not eliminated merely by verified source lookup. Need inspect server worker monkeypatches and isolation next.

## Sustained audit: transport, collectors, agents and research helpers

Confirmed offline/static findings (not fixed):
- HIGH security: utils/rpc_provider.py BSC _PUBLIC registry contains a credential-bearing QuickNode URL in tracked source. Do not reproduce its value. Validity was not tested. Remove from source; operator should rotate exposed credential. Logging/cache code also stores provider URLs, requiring redaction review outside console Tap.
- HIGH forensic integrity: normalize_trace_node on Parity {'type':'call','action':{'callType':'delegatecall',...}} returns CALL, ignoring action.callType. Actual local function reproduction succeeded. Loses delegate storage-context semantics; likewise staticcall variants.
- MEDIUM reliability: _check_rpc_error accepts {'jsonrpc':'2.0','id':1} as None. Actual rpc_batch with mocked empty HTTP array returns [None] and increments provider success. Missing results/IDs must be protocol failures, not successful cached nulls; valid explicit null needs method-sensitive handling.
- HIGH compatibility: console server.worker deterministic path passes no_llm=True; candidate faultseeker.main.main has neither parameter nor **kwargs (AST verified). No wrapper replacing main found in server/guards. Exact pinned fork compatibility does not prove candidate deterministic mode. Worker regression pending.
- HIGH source integrity: loc_parser.get_loc_info on two foo overloads (uint/address, separate lines) returned only last foo at line3. Actual parser reproduction; name-only dict overwrites first overload. Preserve full signature/selector.
- HIGH completion integrity hypothesis: actual AbstractAgent._query_with_json_retry returns {} after4 invalid replies. Transport considers HTTP responses healthy; final guard may not track semantic parse failures. Reproduction of parser confirmed, full worker completion consequence pending. Initial harness omitted JSON_RETRY_PROMPT; corrected harness extracted actual constant and completed.
- ContractInfoCollector ignores chain when txn_link absent and defaults Ethereum; nonempty WAF HTML without Contract Creator is treated EOA, bypassing RPC. Static confirmed behavior, effective console relevance pending. It uses latest bytecode, not transaction historical state.
- TransactionInfoCollector receipt fallback defaults absent status to Success; uses DiGraph for transfer edges, overwriting repeated sender/receiver transfers. Curl subprocess has no own deadline. Console overrides must be considered.
- FundFlowAnalyzer stores token deltas as nested label/amount dicts, while SignalExtractor profit loop tries float(delta), catches and drops errors. Also signals run before address/fundflow classification. Attacker/victim state is not reset on repeated FundFlowAnalyzer.run calls.
- Router builds fixed agents at construction; confidence_gate and should_fallback_to_cloud not used by query path. Unknown cloud aliases count as local/free in its fixed prefix cost policy. These are standalone/hybrid policy gaps, not evidence that current direct console route switches providers.
- HumanInterface: notes choice returns action='n', but pipeline applies notes only action='modify'; first-checkpoint modifications recorded without applying to analysis. No abort UI exists, so earlier abort speculation is not a finding. Name-only confirmation keys collide across contracts.
- Research helpers (offline reproduced): TemporalAttackCorrelator groups two unrelated results with absent identities into one unknown-attacker/unknown-victim campaign; suggest_remediations with {'reentrancy':False} emits3 reentrancy recommendations because it matches serialized key text. Not shown reachable in console.
- Additional research observations: unknown model pricing defaults0 while report says measured; mempool keyword search uses plaintext words against hex calldata; paired_t_test constant nonzero differences returns t0/p1; adversarial fake_events/calldata_note perturbations may not reach the evaluated consumer. Keep research claims unverified; no paper/evaluation changes.

No external/model/RPC calls; RPC tests replaced HTTP with dummy responses and audit hook blocked sockets/DNS. Full module reads recorded above are read coverage, not an all-clear review result. Frontend console.js read through end, but lines roughly65-82 from truncated batch must be reread before marking complete. main.py read1-270 of293. hash_parser initial batch output truncated: still pending full read.


## Cross-chain, frontend race and remaining parser review

Direct offline audit continuation; no agents, external calls, model calls, production edits, commits or deployments.

| Severity / scope | Location | Confirmed evidence | Suggested fix |
|---|---|---|---|
| High report integrity; standalone cross-chain CLI | faultseeker/core/cross_chain_runner.py:242-252 | Actual class methods, mocked analysis return: both {'dry_run':True} and {'analysis_status':'partial','verdict':'INCONCLUSIVE'} produce total_successful=1 and overall_success_rate=100.0. Top vulnerability type is CSV_LABEL_ONLY from input, not a detected finding. run_analysis does exist in main.py; missing entry point is NOT claimed. | Validate explicit completion and results; report dry-run/partial separately; separate ground truth distribution from predicted vulnerabilities. |
| High UI result identity | assets/console.js:32,52 (identical app/web copy) | Existing VM DOM harness modified in memory to defer old result response; start a newer run, resolve old response: new_stream_closed=true, result_has_old_transaction=true, result_labelled_new_run=true, stored_active_run=null. Network blocked. First harness attempt omitted URL global; corrected attempt reproduced. | Capture run identity/generation before await; discard stale responses/events and avoid clearing or stopping newer run state. Verify reachable history/new-investigation flow before claiming a browser E2E reproduction. |
| Medium completeness; text trace rendering | faultseeker/data_collection/trace_visualizer.py:33 | Actual TraceGraphGenerator with CREATE root and CALL child omits child. Graph visualizer traverses CREATE correctly; canonical-to-legacy sets type=call, so structured console impact differs. | Traverse children of call and create; test text-parser creation traces through sequencer. |
| Medium explorer failover | faultseeker/utils/explorer_provider.py:370 | Mock HTTP status0/message NOTOK/result Invalid API Key returned as success, one attempt, no second endpoint; because message masks result when matching errors. | Interpret status and result together; classify key-specific failure and use bounded failover. |
| Medium standalone parser wrapper | faultseeker/utils/solidityParser/constraintExtractor.py:181,193 | Actual wrapper with controlled extractor dict returns literal keys as values: function_name='function_name', input_params='input_params', constraints='constraints'. No application caller found. | Consume dict fields rather than tuple-unpacking keys. Module also imports unavailable project namespace pocshift; verify dependency availability separately. |
| Medium address identity/filtering | faultseeker/utils/utils.py:119-219 | Actual lookup functions: lowercase registry differs from lowercased canonical registry for polygon, avalanche, fantom, arbitrum, pulsechain. Fantom index8 is invalid-length in canonical registry. AddressClassifier consumes lowercase registry. No on-chain ownership validity claimed. | One validated canonical registry with mechanically derived lowercase values; independently verify addresses before changing identity data. |

Other observations requiring scope/proof: auto_select_models ignores prefer_local argument; interactive selector catches ValueError as noninteractive input and silently selects first option. Local retrieve_additional_info prompt has unescaped JSON braces while caller formatting must be checked. Constraint graph recursion has no cycle guard; hash parser exception path returns partial output without explicit parse-failure status. These helpers are not established as current console paths.

Frontend report rendering uses textContent for dynamic report values; no DOM injection reproduced in current console.js. Adapter early-return issue does not mean current UI displays a normal verdict for partial status: renderResult explicitly overrides it to INCONCLUSIVE. Remaining stale-response race is independent.

Kluster unavailable: current tool inventory has no Kluster tool, so no Kluster verification claimed. Existing suite pass counts remain prior baseline until rerun. Audit remains IN PROGRESS; pending inventory is not marked complete.


## Worker lifecycle, source isolation and research integrity continuation

Fresh offline verification at unchanged production heads: console `python -B tests/run_offline.py --tb=line -rs` with FAULTSEEKER_TEST_PIPELINE_REPO pointing at local fb57c3f checkout, FAULTSEEKER_TEST_CANDIDATE_REPO at local candidate, FAULTSEEKER_TEST_CANDIDATE_SHA=893fe1a8067c2b2f6fdcbc0899afa4622db76ac0: **428 passed, 0 failed, 0 skipped (48.31s)**. Frontend `node tests/run_frontend_offline.cjs`: **19 passed, 0 failed, 0 skipped (127.9994ms)**. Candidate `python -B tests/run_offline_depth.py tests`: **310 passed, 0 failed, 0 skipped (25.17s)**. `python -B tools/sync_static.py --check` and `git diff --check` exit0. These are baseline results, not coverage of newly found defects; no live providers tested.

Confirmed, not fixed:
- HIGH worker lifecycle: server.py:1058-1114 guarded queue exception exits without terminating/joining child. Actual AST-extracted guarded with fake alive process and queue.get raising OSError recorded only start/end, lock released, status stopped, worker_reaped=False. No real child spawned. Reap worker on every exit before releasing single-run lock.
- HIGH source integrity: actual ContractDownloader methods with mocked filesystem show failed download for B can parse stale A files into B cache. Shared ./temp2 is not isolated. Same harness confirms unconditional ./Implementation deletion request; no actual deletion performed. ContractName='../../escaped' escapes scratch root. Explorer control of that value is not demonstrated; do not call remote exploit verified. Use per-run temporary directories, containment validation, explicit failure, and verified cache identity.
- MEDIUM benchmark build: Dockerfile.benchmark:9 COPY references THREAT_MODEL.md, EVALUATION_PROTOCOL.md and TDSC_ROADMAP.md, all absent from this local checkout. Docker build not run.
- MEDIUM metric validation: actual classification_metrics([1,0],[1.0]) reports n2/F1=1 despite absent second prediction; brier_score([1,0],[]) returns0. EvalRow accepts infinite trace feature values as present. Reject mismatched lengths/nonfinite values. No frozen evaluation rerun.
- HIGH evaluation integrity: run_adversarial_eval.py:26-44 computes fixed .85 base minus fixed penalties rather than invoking SignalExtractor/TIG, despite claiming real system robustness. sync_results.py then copies it to canonical research results, invents fixed sample count231 and duplicates full-system row as an unexecuted hardening ablation. build_honest_latex_tables.py hardcodes retention>=.94 and231 samples without validating them. Do not cite these as detector measurements.
- HIGH evaluation scope: run_honest_experiments.py:74-84 LLM-only is a formula with no LLM; full-system scorer is feature calibration, not pipeline execution; routing ablation simply calls same scorer. Real trace features do not make these full-system/model benchmarks. Keep existing frozen artifacts unchanged, disclose scope.
- HIGH calibration semantics: retrain_calibrator.py:40-54 and kfold version assign count/gas proxies to fields named code_evidence/llm_confidence/state_delta; deployment scorer supplies different semantics. K-fold validation does not repair train/inference feature mismatch. Single retrain script evaluates on training rows and writes model on import. Do not run either during audit.
- MEDIUM external baseline metrics: ingest_external_baselines.py:181-184 groups per_chain_f1 by tx-hash prefix rather than chain; CI resamples those buckets. Static confirmed; numerical reproduction pending.
- MEDIUM selector provenance: localization helpers use SHA3-256 when Keccak unavailable; actual transfer selector comparison differs. Installed Crypto makes fallback inactive here. Helpers harvest ground-truth function names and guess signatures, choose shortest collision name, and ignore contract identity in legacy matching. This is not independently verified ABI resolution.
- MEDIUM prediction generator: generate_pipeline_predictions.py accepts analyzer but never invokes it, sets uniform candidate scores .95 and calls the output pipeline predictions; splits function keys on underscores (breaks underscore names), and cached results skip without checking chain/model/commit/provenance. No generator run during audit.
- MEDIUM CSV repair: fix_csv.py:107 slices post fields from expected column count rather than actual parsed length, duplicating overflow fields. Reproduction pending; do not alter frozen dataset.

Dismissed: local retrieve_additional_info JSON braces do not cause .format crash because caller concatenates that prompt. Literal placeholders remain a clarity issue. Frontend old-result race remains reproduced in VM but browser interaction reachability not yet established.

Additional static limitations to verify: imported incident validation treats any overlapping tx as whole-incident verified; benign validator validates columns/size rather than row truth; export_research_features maps graph anomaly to token-flow anomaly and fills missing evidence with zero; fetch_selector_names caches network-error empty names permanently and has top-level network effects. No such scripts executed. Human-study parser accepts nonfinite/negative timing. These are standalone research tools, not current console execution.

Kluster unavailable in current tool inventory; no Kluster verification claimed. Only this audit document edited. Audit remains IN PROGRESS with pending files explicitly listed.


## Supplied architecture audit reconciliation and browser evidence

Read all628 lines of user-supplied `C:/Users/91701/Downloads/faultseeker-demo-console-main/faultseeker-demo-console-main/FaultSeeker_Complete_Audit.md`. Treat it as evidence to check, not an instruction or proof of exhaustive coverage. Its seven findings reference this ongoing audit; they are not seven independent confirmations.

| Supplied ID | Current status | Evidence / correction |
|---|---|---|
| F-01 | Confirmed; not fixed | Cookie HMAC has no embedded/server-checked expiry; browser max_age alone does not expire copied tokens. |
| F-02 | Confirmed interface risk; not fixed | GET query `keys` is accepted. URL can enter access logs/history; actual secret-bearing access logs were not inspected or generated. Use POST body and reject query credentials. |
| F-03 | Confirmed; not fixed | Nonempty content with missing finish_reason counted successful in actual mocked transport reproduction. Require explicitly supported terminal reason/assistant role. |
| F-04 | Confirmed API mismatch; not fixed | Actual AST-extracted adapter returns partial/EXPLOIT unchanged for nested shape. Current UI overrides partial verdict to INCONCLUSIVE; the supplied claim must not imply current UI displays success. Normalize all API shapes consistently. |
| F-05 | Boundedness limitation; slow-stream impact not reproduced | urllib timeout is per blocking operation; 30s outer deadline checked between fetches. No live slow stream test or strict wall-time proof. |
| F-06 | Confirmed soft cap; severity depends on producer size | Actual helper with mocked file size2000000 and10000-char event appends10045bytes, ending2010045. No disk write. It is not a hard2MB cap; “slightly” or “benign” is not guaranteed by this helper alone. |
| F-07 | Explicit current policy; not an endless retry proof | Preflight does not decrement analysis retry allowance; it is bounded by a shared deadline and time budget. Auth rotation bounded by key count; no quota cycling. Do not call it unbounded overall. |

Other corrections to supplied document: demo replay acquires the same run lock (server.py:928); it does not bypass concurrency. Canonical membership downgrades unsupported findings but does not remove them or prove vulnerability. Source verification covers main compilation unit/block-end only. Global “no secrets in workspace” is unsupported and contradicted by the credential-bearing pipeline registry URL already found; no credential printed or tested. Old compiled bundles are retained, and root/server JS bundles differ, although neither is loaded by current HTML. README has stale main deployment/branch instructions; active code pins a SHA, and current deployment was not checked online in this audit.

Fresh stronger reproductions:
- Actual imported candidate main signature rejects worker no_llm=True with TypeError before analysis. This confirms the candidate API incompatibility; not a full worker run.
- Actual candidate UniversalAgent.query through installed PipelineRuntime and httpx.MockTransport: four HTTP200 replies containing invalid JSON return {}, endpoint failure=null, analysis calls ok4/failed0. Network blocked, dummy credentials, temporary working directory. First attempt used incorrect constructor keyword and failed; corrected task/model_name call completed. This proves semantic failure invisibility at real agent/session boundary. Full downstream false-completion consequence remains to reproduce.
- Actual Chromium using only intercepted local files/dummy APIs, external proxy blocked: start old run, wait for delayed report, Recent runs -> View report -> New investigation -> start new run -> resolve old report. Browser shows old transaction labelled Run newrun and clears new active-run storage. All controls were clicked normally; race is user-reachable, no private function invocation.
- `python -B tests/browser_checks.py --offline` exited1 at line180: expects20 `.finding` cards in saved capture. All earlier assertions were reached successfully, but suite does not emit a final passed count on failure, so do not present it as passing. Saved Stage1 capture has unanalysed calls, not scored findings; test assertion is stale relative to honest separation. This needs correction with meaningful observation-pagination checks, not changing report to satisfy obsolete assertion.

Only audit document changed. Kluster tool unavailable. No model/RPC requests, project application changes, commits, pushes or deployment.


## Remaining importers, parser and browser checks

Confirmed observations, no production fixes:
- LOW mobile UI: actual offline Chromium at360x800 opening BNB preset gives documentWidth501 and pickerRight501. Preset minimum width and left anchor overflow viewport; browser baseline did not open this control. Constrain/anchor popup to viewport and add interaction regression.
- MEDIUM source integrity: actual get_loc_info on incomplete Solidity contract/function returns C/foo despite parser syntaxErrors=1. loc_parser.py:138-181 removes error listeners without checking parse errors. A modern custom-error control parsed with0 errors. Reject incomplete parses or return explicit unverified status; do not mislabel this as proven modern-grammar incompatibility.
- HIGH local utility security, conditional on operator input: contract_info_collector.py:192-194 standalone script applies eval to attack_tx CSV cells. This permits Python expressions in a supplied dataset. No console/web caller established; no malicious payload executed. Use literal parsing plus strict list/hash validation.
- HIGH research assurance: verify_paper_validity.py:10-14 checks only FAILED=0 substring, ignoring process return code, MODULE_ERRORS and skipped coverage; lines32-86 infer provenance from metadata strings/counts and thresholds, not actual execution evidence. run_tests_nopytest.py:95 skips all parameterized/fixture functions, ignores test classes, drops pytest mark semantics and exits normally even after failed tests/import errors. Do not use its all-real/all-tests-pass output as verification. Current recorded310 pipeline passes came from actual pytest via run_offline_depth, not this shim.
- MEDIUM diagnostic metric bias: detailed_miss_analysis.py:43-53 excludes missing predictions and empty scored lists from denominator, then line85 divides by zero if no evaluable rows. Function-only matches ignore contract identity. This script was read, not run against frozen results.

Static limitations, not independently verified incident labels: benign collectors label ordinary contract calls benign without incident review; collect_benign_traces.py:217-219 can mark null trace/receipt as successful zero features. Imported source regexes collect arbitrary32-byte values; DeFiHackLabs infer_chain assigns one chain to every hash in a file. These importers generally mark candidates pending review, which is appropriate; no specific historical mislabel is claimed. build_research_exploit_pool counts duplicate verified input rows toward target. HuggingFace importer labels candidates explicitly, but treats every non-1 label as non-scam and uses predictable temporary filenames. No downloads or importer execution.

Chart script uses a hardcoded246-transaction title and only configured palette chains; missing categories are omitted and empty numeric data can fail percentile calculation. No charts regenerated. Only this checklist edited; Kluster remains unavailable.


## Test-suite source coverage completed

All listed pipeline test Python files and offline runners have now been read in full (empty tests/__init__.py accounted for). No tests were edited. Important coverage boundaries:
- test_deep_trace_objects.py:98 explicitly asserts the legacy omission of descendants under CREATE; it preserves behavior, not correctness for that case.
- test_deep_rpc_normalization.py:28-30 builds Parity action without callType, so delegate/static semantics are not tested despite variant coverage and frozen hashes.
- test_function_target_memo tests address-scoped memo identity but not distinct repeated-pattern deduplication or cross-address source substitution.
- test_honest_eval metric tests omit mismatched vector lengths/nonfinite values. Selector tests register target names and validate the same name-derived resolution; no independent ABI provenance is established.
- test_orchestrator_wiring.py:158-170 claims model-present calibration but explicitly permits None. Cost tests exercise estimated arithmetic, not actual billed tokens. test_research_experiment_suite checks formula ordering rather than executing detector ablations.
- test_reentrancy_state_signals uses synthetic call/storage events and tests structural recurrence plus selected negative cases. Passing it is not verified exploit detection or live-chain completeness.
- Offline runners block Python socket/DNS audit events and remove common inherited credential variables; subprocess network calls are not independently sandboxed by those hooks. Reviewed tests use mocks, but do not describe the hook as an OS-wide network firewall.

No fresh suite run needed after read-only source review; prior exact test results and failing browser assertion remain recorded above. Generated parser code and data/artifact inventory remain pending. No chain correctness pass claimed.


## Data integrity pass (structural, not incident adjudication)

Read every row of13 benchmark CSVs with csv.DictReader: no overflow/missing cells. Raw benchmark115 rows; fixed231 rows across8 chains; benign traces1000 and contract benign100; research pool1059, with0 duplicate(chain,hash) pairs. Its26 repeated hashes occur across chains and are not automatically defects. No evaluation rerun or data modification.

Parsed all115 ground-truth JSON files and inspected all278 location entries. One filename/transaction_hash mismatch confirmed: benchmark/ground_truth/0x72a252277e30ea6a37d2dc9905c280f3bc389b87f72b81a59aa8f50baebd8eaa.json:6 contains0x6439d63cc57fb68a32ea8ffd8f02496e8abad67292be94904c0b47a4d14ce90d instead. This can bind a target to the wrong prediction when consumers key by filename. Correct identity requires source adjudication; do not silently rename/replace frozen ground truth. Three entries have extra # segments (SwarmMarkets and UnizenIO), and22 have empty member/line markers. The initially flagged address is uppercase0X prefix, not an invalid-length address; do not report it as malformed address. Structural scan is not line-by-line incident provenance validation.

Local Hedgey cashout ground truth lists USDC transferFrom at the token/proxy, not campaign creation/cancellation. That supports treating setup and cashout as different analysis scopes, but is not independent proof of the exploit mechanism. Do not tune expected output to this file.

README.md:420 says MIT while LICENSE begins Apache2.0; confirmed documentation mismatch, no legal interpretation/change made. README claims and DATASET_INTEGRITY.md overstate staged non-scam-address candidates as benign traces; their own detailed import notes preserve candidate-only status. Runtime/cost and reentrancy JSONs contain aggregate claims without per-transaction supporting runs in those files; status is unverified, not a claim that every number is fabricated. Their provenance must be established before citation. Current audit does not access external incident sources.


## Semantic failure follow-through: target narrowing

Confirmed HIGH completion-integrity gap, offline controlled-boundary reproduction. FunctionAnalyzer._review_function_calls at function_analyzer.py:544-560 starts with6 candidates and receives{} from its agent. Because len({})<6, it replaces the candidate set with{}, then enters0 function-analysis loops. Actual method extracted from current source ran unchanged with controlled query return; _prepare_children_call_memo received[]. No network/model call in this reproduction.

Actual PipelineRuntime.annotate_result with controlled transport summary(ok4/failed0), function_analysis started1/completed1 and an empty WallCapLedger leaves status unset and stage_completed=stage-3. Applying server.py:869's default yields completed, despite scored_functions/evidence_cards empty. This is a boundary composition test, not a full worker/live run. Earlier real UniversalAgent+MockTransport already established invalid JSON can become{} after4 HTTP200 responses with a healthy session. Together these establish a concrete failure path; do not claim the exact historical run followed it.

Correction/limitation: malformed JSON at _select_task inside a guarded function loop can yield unknown_exit and therefore partial; that path is already guarded. The narrowing step occurs before those loops, so no wall record exists to catch it. Suggested fix: raise an explicit semantic response error on exhausted JSON parsing; validate the narrowing schema and distinguish a deliberate empty selection from unavailable analysis. Track required target-stage work explicitly, and never infer completion solely from FunctionAnalyzer.run returning. Add a real-agent through run/worker regression before claiming complete end-to-end coverage.


## Historical-run ledger reconciliation

Completed remaining ledger read through line975. Historical correction order matters: legacy provider-factory routing, target memo and descendant counts were already corrected in candidate893fe1a; the current audit findings concern other paths and must not reopen those as unfixed without new evidence. Full JSON semantic failure and narrowing remain distinct from HTTP health, wall-cap classification and those previous patches.

Last recorded real Mercury run d24102427b03 had95 successful transport attempts but partial/unvalidated analysis, with Sourcify provider_limited before Hedgey source binding. It does not validate the source-delivery fix. Earlier completed transport runs gave wrong explanations; no correct chain pass is supported. Reading this ledger is not fresh runtime/deployment evidence. No calls or retries initiated.

Review continuation checkpoint: application source and pipeline test files read; generated ANTLR code, retained compiled frontend bundles and remaining data/artifact line-level coverage are still explicit gaps. Structural scans of data do not replace incident adjudication. Target-narrowing reproduction above changes the next corrective action: semantic parse failures must propagate before accepting empty candidate sets. Production files remain unchanged during audit-first stage.


## Generated parser structural check

Parsed ASTs of all generated Python files: Lexer937lines, Listener867, Parser8648, empty initializer. Full-file AST inspection found no executable eval/exec, file/network/process-call candidates; substring scanner matched nameValue visitor/context methods, which are false positives. Read parser semantic-predicate dispatch8557-8648: standard precedence predicates only. This is structural screening and a bounded manual read, not full line-by-line grammar correctness verification; generated files remain pending for that scope. Their generation provenance and correspondence to original grammar are not independently established. No parser regeneration, dependency install or source edit performed.


## Packaged surface and saved capture check

Current HTML in both surfaces references only console.js/console.css. FastAPI mounts app/web at root. Retained index-B9Da4QyI.js bundles are different (407308 vs411952bytes); retained index-ut3zQWOW.css files are identical40192bytes. They are reachable static artifacts but are not loaded by current HTML. No active legacy-bundle exploit is established. Full bundle semantic review remains pending; do not count checksum/URL screening as full review.

Parsed static api/config and api/capture completely as JSON. Capture has analysis_status=stage1_complete, stage_completed=stage1, stage2_bypassed=true, yet analysis_complete=true. Its limitations correctly disclose skipped function analysis/scoring. This is a confirmed ambiguous API completion flag, not evidence that current UI presents a completed full analysis; caller expectations must be traced before selecting severity/fix. tools/sync_static.py regenerates HTML/config/current assets, not api/capture, so its clean check does not validate capture integrity. Raw capture is historical deterministic data, not current chain correctness proof.

Only audit artifact changed. Kluster remains unavailable in exposed tool inventory. No production source edit, external request or deployment.


## Capture consumer and CSV repair reproduction

Capture flag scope resolved: assets/console.js:55-56 uses analysis_status, not analysis_complete, and explicitly renders saved/stage1_complete verdict as STAGE1ONLY. Existing frontend regression asserts skipped LLM scope. server capture route serves saved JSON. Thus analysis_complete=true is an ambiguous historical API field, not a confirmed misleading current full-completion UI bug.

Confirmed MEDIUM local research utility defect at benchmark/fix_csv.py:107. Executed the actual AST assignments for post/analysis_fragments/analysis_joined/row with synthetic parsed=['tx','part1','part2','SWC','DASP'], expected_cols4, analysis_idx1, tail_col_count2. Actual output=['tx','part1,part2','part2','SWC','DASP'] has5columns instead of4. Fix post slice relative to len(parsed), and verify row width before writing. No full script execution or frozen dataset write; effect on historical repaired data not inferred. This closes the earlier pending numerical reproduction.


## External baseline grouping reproduction

Confirmed MEDIUM research metric defect at benchmark/ingest_external_baselines.py:181-193. Actual imported per_chain_f1 with two synthetic Ethereum rows (one true positive, one false negative) returns[1.0,0.0] when hash prefixes differ. Changing only the second hash prefix to match the first returns[0.6666666666666666], while chain/labels/predictions remain unchanged. evaluate:158 bootstraps these hash-prefix buckets, so reported interval lacks claimed chain semantics. No frozen evaluation or output write. Ingested schema currently discards chain, so fixing grouping also requires preserving explicit validated chain or joining trusted transaction identity; do not infer chain from hash. This closes the earlier pending numerical reproduction.


## Lexer-versus-parser failure boundary

Actual installed ANTLR/generated modules and get_loc_info tested offline with three synthetic sources. Valid contract: lexer0/parser0, returnsC. Same contract with illegal @ before function: lexer1/parser0, returnsC. Missing closing braces: lexer0/parser1, returnsC. Thus merely checking parser.getNumberOfSyntaxErrors is insufficient: lexer errors must be retained separately. Both current antlr_listener and get_loc_info remove error listeners and publish recovered trees without an explicit invalid-source status (loc_parser.py:138-181). Regression must cover both categories and a valid control before fixing. No generated grammar edit or claimed Solidity-version incompatibility; no file/network side effects beyond imports and this audit note.


## Invalid source through downloader extraction

Executed actual AST-extracted ContractDownloader.parse_contract unchanged with real get_loc_info and installed ANTLR, isolated temporary C.sol containing illegal @ token. Result has foo with nonempty source content and no error/status field. No network; temporary source removed automatically. This extends parser reproduction through the real downloader extraction boundary, not the full console worker. run:203-206 accepts nonempty extraction and writes its address/chain cache; that cache-write consequence is static control-flow evidence, not an actual cache write in this test. Console replaces later source retrieval with historical verified source, but initial downloader still executes; do not imply this isolated reproduction proves current displayed source is malformed. Required fix must prevent cache publication of recovered invalid parses and preserve explicit unavailable-source handling.


## Explorer deep-trace reproduction

Confirmed capability boundary at app/explorer_trace.py:107-118: actual AST-extracted rows_from_calltracer with1024 synthetic CALL frames raises RecursionError at interpreter limit1000. Identity validators were controlled no-ops to isolate traversal; no network or on-chain fixture. This is not proof the full worker fails at that depth because pipeline main/import can raise the process recursion allowance20000. Direct library calls at default limit remain affected. An iterative traversal would remove this dependency; integrated worker coverage must preserve identity, child ordering and failure metadata. Earlier pending reproduction is now resolved at this bounded scope.

Inventory checkpoint:66 console files and339 pipeline files;13 and162 respectively still labelled pending, predominantly artifacts/generated bundles/grammar/data. Read-status follow-through also remains open. Do not claim an exhaustive audit from source/test reads plus structural artifact scans.


## Saved research-table cross-check

Read complete baseline/adversarial CSVs in honest_results and baseline/ablation/adversarial CSVs in research_results. Their numbers reflect the previously traced formula/proxy scripts, so their presence does not prove actual LLM/full-system execution. research_results adversarial table assigns231samples to each fixed-score helper outcome; ablation table includes a hardening row copied from full-system results. Scope defect confirmed by existing generating code plus artifacts, not by rescoring.

reports/SYNTHETIC_DO_NOT_CITE/README.md:23-28 describes current research_results as11059transactions/F1.969/FPR.003, but current table has1231transactions/F1.759/FPR.021. Confirmed stale documentation, separate from whether the current metrics are valid. README:37 claims regeneration requires API keys; reviewed formula scripts do not establish actual inference. Calibrator CV metric copies agree numerically; this does not resolve train/inference feature semantics or establish independent model accuracy. No paper/dataset/result edits or external requests.


## Fixture structural provenance continuation

Parsed every console JSON fixture, inventoried object counts and SHA256s, and compared stored historical ABI runtime to stored RPC result: equality holds. Hedgey verified trace fixture has5Parity call rows and cashout hash2606...5739; ABI fixture explicitly binds setup hasha17f...a517 at blockend. These are deliberately different transactions, not a fixture mismatch. Other explorer fixtures are provider-shape examples with separate metadata; structural scanning alone does not establish fresh chain verification or full fixture semantic review. Initial metadata print was overly broad/truncated; subsequent bounded inventory avoids treating truncated output as a full manual read. No fixture or expected result modified, no external endpoint contacted.


## Cancellation lifecycle scope reconciliation

Retraced server.py:1058-1117 and1213-1224 against tests/test_server.py:432-464,618-633. Early cancellation sets the event even before proc registration; parent loop checks it and terminates the child. Cancellation after observed done/end is rejected via finishing flag, and an already dead process is not relabelled cancelled. Existing offline baseline exercised these mocked contracts; no new runtime test performed here. These cases are not outstanding confirmed cancellation bugs. The separate confirmed queue-exception cleanup defect remains: exceptions before proc.join bypass reaping while finally releases lock. Real process/OS race coverage still ends at mocked boundaries; do not equate these tests with complete child-process cleanup verification.


## Replay retention control-flow confirmation

Confirmed MEDIUM resource-retention defect: server.analyze replay branch927-999 returns before live-run pruning1013-1016. AST of actual async analyze confirms terminal Return999; only runs.pop calls in replay branch are startup/history failure handlers937/996. Replay finally989-991 closes bus/releases lock without removing completed run entries. Therefore successful replay-only traffic accumulates run entries and each bounded RunBus in memory until restart or a later live analysis prunes them. This is static control-flow proof, not a measured memory-load or remote denial-of-service demonstration. Shared run lock still applies; no concurrent-run bypass claimed. Suggested fix: shared retention helper on both admission/finalization paths, preserving active runs and disk-history policy; regression should execute repeated successful replays with dummy files and verify retained terminal-run bound.


## LaTeX export mismatch confirmation

Confirmed HIGH research-report integrity mismatch: reports/research_results/research_tables.tex:12-22 says11059transactions/F1.969/TP1023, while adjacent baseline_comparison.csv:5 says1231transactions/F1.759/TP154. reports/honest_results/honest_research_tables.tex:18 saysF1.859/TP174/FPR0, while adjacent baseline_comparison.csv:5 saysF1.7586/TP154/FP21/FPR.021. Adversarial LaTeX claims250samples while current CSV claims231 and has different fake-event effect. These are directly observed artifact disagreements; which run each table came from is not established. Do not silently regenerate or edit frozen artifacts/paper. Suggested remediation requires explicit run manifests/data hashes and export consistency checks, preserving old outputs with honest scope. No evaluation rerun or paper change.


## Confidence parsing boundary matrix

Actual ConfidenceScorer._compute_llm_confidence inputs/results: ['0.5%']->.5 (should.005), ['1%']->1 (should.01), ['2%']->.02, ['80%']->.8; stringNaN,numericNaN,infinity andTrue all->1. These extend the earlier reproduced1%/NaN defect with discontinuity and invalid-type coverage. No model/RPC used or scoring dataset rerun. Root cause: percent marker removed before magnitude-based scale inference, bool accepted as int, and nonfinite values clamped before validation. Fix must explicitly parse percentages, reject bool/nonfinite and preserve valid numeric/label semantics. Actual final ranking/calibration effects depend on other components and model; do not claim these component results alone establish a particular historical verdict.


## Malformed calibrator shape reproduction

Actual LogisticConfidenceCalibrator.from_dict accepts feature_names[a,b] with only one weight/mean/scale and trained=true. predict_proba(a1,b0) and predict_proba(a1,b1000) both return.7310585786300049; b is silently ignored through zip truncation in _scale:163 and predict_proba:76. Confirmed model-shape integrity defect with synthetic in-memory model, no file/model weight changes. Existing shipped model has matching vector lengths; no claim it currently suffers this malformed shape. Validate vector lengths, unique supported feature names, finite numbers and positive scales during loading; reject invalid artifacts so existing heuristic fallback can be explicit rather than presenting an incomplete model as calibrated.


## Generated listener behavior accounted for

Full AST inventory of SolidityListener.py867lines shows190methods, each exactly pass; no other class-body statements. Manually read module header/import branch/class declaration/footer delete. Thus listener base contains no custom execution logic beyond imports/type annotations. All5 location-parser enter/exit overrides match generated callback names; no missing-hook naming defect found. This closes listener behavior review, not generated lexer/parser grammar correctness or proof of generation provenance. No new runtime tests or production edits.


## Generated lexer executable behavior review

SolidityLexer.py AST: imports/version-based TextIO import; serializedATN function returns one15929-integer literal list; class has only __init__, calling Lexer constructor, checkVersion4.13.0 and LexerATNSimulator, with actions/predicates=None. No custom lexer actions/predicates found. Initial literal check excluded unary negative constant-1; corrected ast.literal_eval confirmed every table item integer. Installed runtime4.13.2; successful earlier parsing controls establish local compatibility for tested inputs, not all grammar constructs. Serialized transition-table grammar semantics remain unverified; this is not full line-by-line grammar review or original-generator provenance verification. Only audit note edited.


## Generated parser recovery control flow

AST inventory: SolidityParser has99direct methods,95context classes and95RecognitionException handlers. Read sourceUnit control flow in full: top-level alternatives loop then explicitly matchEOF, standard reportError/recover and finally exitRule, returning context. Therefore missing EOF enforcement is not the cause of accepted malformed sources. Recovery is normal generated behavior; wrapper must inspect both lexer/parser errors before walking/publishing. This narrows the fix to application boundary validation rather than disabling generated recovery or editing grammar tables. Other95rule bodies/serialized grammar still require remaining semantic coverage; no exhaustive grammar claim.


## Receive/fallback source localization omission

Read generated contractDefinition1388-1463 and functionDefinition2463-2512 control flow. Generated grammar has separate receiveFunctionDefinition/fallbackFunctionDefinition rules and callbacks, while CustomizedSolidityListener overrides only ordinary enterFunctionDefinition. Actual get_loc_info on synthetic contract containing receive(), fallback() and foo() returns only foo. Confirmed source-localization coverage gap for special entry points, relevant to proxy/fallback investigation; full console impact depends on verified source override and target selection. Earlier statement that existing5callbacks match generated names remains true but does not prove all required callbacks implemented. Add explicit special-function identities/locations without conflating unnamed legacy fallback and ordinary functions; test downloader extraction and consumers. No production edit or provider call.


## Solidity construct compatibility controls

Actual installed generated lexer/parser on synthetic Solidity^0.8.20 sources: contract custom error/revert parses0lexer/0parser errors; file-level uint256 constant parses0/0; file-level type Wad is uint256 plus foo(Wad) produces0lexer/3parser errors. In every case get_loc_info returnsC. This confirms a specific user-defined-value-type grammar limitation; do not generalize to all modern Solidity or custom errors. Wrapper error propagation is necessary but cannot add unsupported grammar semantics. Dependency/grammar upgrade would need independently verified local source and regression coverage; no downloads/regeneration or compatibility fix claimed. Full console impact still depends on source retrieval override and analyzed compilation unit.


## Staged import manifest scope reconciled

Read five complete dataset/source/import manifests. HF summary explicitly labels all10000 rows address_label_benign_candidate and requires downstream spot checks; validation JSON establishes schema/duplicates/size only. GitHub summary explicitly marks1128 rows pendingRPC,200unknownchain. Incident manifest has153manual-review rows/26missinghash,62overlap rows, not universal verification. Therefore these manifests themselves preserve candidate scope; misleading stronger claims arise in higher-level docs/report interpretations already flagged. No new defect asserted merely because data remains staged. Earlier full CSV structural scan agrees on row counts. Source URLs were read as metadata without external requests. No result or paper modifications.


## Generated context callback consistency

Checked every generated context-class AST:95classes invoke190enter/exit listener callbacks, all present on generated SolidityListener. No missing generated callback name found. Custom listener omission of receive/fallback remains a separate confirmed defect; base callback consistency does not negate it. Context inventory includes constructor/error/modifier/receive/fallback/import/type/expression/assembly rules; presence alone does not prove semantic correctness for every modern construct. Serialized grammar and full rule-body semantic review remain open, with value-type negative control already recorded. No application source changes or fresh test-suite run.


## Ground-truth manual batch1

Read first6sorted ground-truth artifacts completely: LPMine,ChannelsFinance,WiseLending,Zoomer,ZunamiProtocol,Soda. No external incident adjudication. Zoomer has a raw-selector target and empty line marker, already within structural limitations. New confirmed internal inconsistency: Soda0x07e556...f308.json:11 location key ends21957:94 while value at13 ends657:13 for same contract/function. Which source coordinate is correct is unverified; consumers using keys versus values can disagree. Record and adjudicate against original compilation/source before any frozen-data correction; no replacement coordinates invented. Timestamp formats differ (Soda slash-date/local-looking text versus UTC labels), so chronology requires explicit normalization rather than lexical sorting. Remaining109ground-truth files not marked manually read by this batch.


## Ground-truth manual batch2 and coordinate interpretation correction

Read next10sorted artifacts fully: FDP,DODO,Game,bZxProtocol,GoodCompound,UnverifiedContr0x452E25,GFOX,Dexible,EFLeverVault,secondSoda.16/115now manually read by these two batches; structural coverage remains separate.

DODO key44054:8 versus value1419:50 and both Soda key21957:94 versus value657:13 demonstrate differing coordinate representations. Correction to prior characterization: these could represent byte offsets versus line spans; without an authoritative schema, numerical disagreement alone is NOT a proven erroneous coordinate. Retain as unresolved coordinate semantics and consumer-consistency risk, not a confirmed wrong ground-truth location. Do not change either representation to make them equal. Repeated Soda incident across different hashes is not automatically duplicate ground truth. GFOX disclosure year2025 versus incident2024 requires source verification, not an inferred typo. Missing source filenames/line markers remain known completeness limitations.


## Fix cycle1: combined-audit console remediation

Current local production changes (uncommitted, fix/all-chain-validation):
- Worker queue/history exception cleanup now terminates/joins/kills as needed in finally; releases run_lock only after child death confirmed. A stubborn child leaves slot held with explicit cleanup error, requiring operator recovery. Two simulated process regressions plus cancellation controls pass; real OS child behavior not yet tested.
- SuppliedF03: nonempty response requires finish_reason=stop and assistant role before transport success; known unfinished reasons retain prior classification. Missing/unknown marker regressions first2failed, nowpass; unknown marker/body not exposed.
- SuppliedF04: nested transaction/classification report shapes with unsuccessful statuses normalize verdict toINCONCLUSIVE using copied classification; raw stored report unchanged. Four regressions firstfailed, nowpass. CurrentUI already guarded partials; this repairsAPIconsistency.
- SuppliedF02: GETdiagnostic rejects keys query parameter; POSTJSON carries supplied keys, validates basic fieldtypes, runs existing bounded diagnostic in threadpool. Existing internal helper callers preserved. Rejecting a URL cannot erase prior proxy logs; no historical-leak claim. Regression firstfailed, final3focusedpassed.
- SuppliedF01: signed issuance timestamp and7day server expiry; future/tampered/legacy tokens rejected, password rotation invalidates signature. Copied cookie regression firstfailed, nowpass. Existing cookies require login after eventualdeployment.

Test-double regression found during combined testing: replacing shared threading.Thread affectedASGIruntime; now test replaces server.threading namespace only. No application threadpool policy changed.

Exact latest command: python -B tests/run_offline.py -k 'test_server or test_model_endpoint' --tb=line -rs ->176passed,263deselected,0failed,0skipped,8.61s,exit0. git diff --check exit0. Full attempted suite earlier:367passed,10failed,7skipped,46setupErrors; cannot report green. Both prior pipeline checkout paths fail git rev-parse; candidate .git points to temporary pin's .git/worktrees. No fetch/clone/revision substitution made. Full pinned/candidate verification remainsblocked by localmetadata/source availability, not repaired by mocks. Frontend last run19passed/0failed/skipped. No live model/RPC, push, merge or deploy. Kluster unavailable throughout; no Kluster verification claimed.

Both audit backlogs remainopen: semanticJSON failure, UIgenerationrace, sourcecache/isolation, ranking, parser, deterministicruleevidence, calibration, replayretention and other listedconfirmed defects still needfix/testing. F05slowstream remainshypothesis; F06softcap confirmed needshardbound; F07boundedpreflight policy needs explicit decision/evidence, not falseinfinite-retry diagnosis.


## Fix cycle2: semantic integrity, UI identity and resource bounds

Local fixes now include query-local/thread-local JSON extraction tracking: exhausted parse recovery latches invalid_response/invalid_json; a later successful parse, including valid{}, clears parse-failure state. Query/send failures cannot be swallowed into healthy completion. Control tests passed; exact real pinned/candidate agent coverage remains unavailable due checkoutmetadatafailure. Finite diagnostic categories unconfirmed_finish/invalid_role/invalid_json allowlisted without body leakage. Command python -B tests/run_offline.py -k 'test_pipeline_guards or test_model_endpoint or test_server' --tb=line -rs ->209passed,4skipped,228deselected,8.33s; four skips explicitly require exactpin. Later metadata focused4passed.

Frontend report retrieval, status polling and allEventSourcecallbacks now bind to initiating run/viewgeneration. Three new regression tests firstfailed independently, final node tests/run_frontend_offline.cjs ->22passed,0failed/skipped. Static assets synchronized. python -B tests/browser_checks.py --offline ->11checks passed, zero uncaught browser exceptions; corrected obsolete assertion now checks0findings and20->40observed-callpagination in actual savedStage1capture. Specific delayed race browser interaction not yet rerun; VM regressions are not claimed as browser raceproof.

SuppliedF06 hard eventfilecap fixed: serializedUTF8record size plus currentfilesize mustfit2,000,000bytes; check/write protected byhistory_lock; completeJSONLrecords only. Three cap/control regressions pass. Initial hugepytestparameterID caused path/setup errors; changedparameters tonumericlengths, rerun3passed. No secretused.

Replayretention fixed using shared_prune_finished_runs in replay/livefinalization, preserving active/cancelling andalive/uncertainworkerhandles, retaininglatest20terminalstreambuffers. Diskreports/historypolicyunchanged. python -B tests/run_offline.py -k 'finished_run_retention or test_server' --tb=line -rs ->118passed,327deselected,7.31s. Added realASGIendpoint25successfuldummyreplayrequests: helper+endpoint tests2passed,444deselected,3.64s, verifies20retainedclosedbuffers, unlockedslot andoldreportstillondisk. Not a liveprovider/loadtest.

Allchanges uncommittedonfix/all-chain-validation. No externalrequests/push/merge/deploy. Kluster unavailable. Otherauditfindings andall16chaincorrectnessrequirementsremainopen.


## Current offline verification after console fixes

python -B tests/run_offline.py --tb=line -rs with unavailable external checkout envvars absent:384passed,0failed,63skipped,10.61s,exit0. All63skips are explicit pinned/candidate integrations; this does not replace earlier failed explicit-checkout verification. No SHA substitute or downloaded source. Explorer iterative conversion regression firstRecursionError, final explorer module55passed/10skipped.1024frame synthetic traversal preserves path/callType/error; no live tracequality claim. Static sync check andgitdiffcheck exit0. Frontend latest22passed; offlineChromium11checks passed previously. Remaining pipeline defects cannot be labelledfixed fromconsole tests. No push/merge/deploy orlivecalls.


## Exact source recovered and pipeline remediation started

Recovered exact local commits from intact existing objectstore through pipeline-address-context-fix. Created separate detached local worktrees pipeline-pin-offline-verified atfb57c3fad63784b7a63dc7fdf1845364c76ce0b7 andpipeline-candidate-offline-verified at893fe1a8067c2b2f6fdcbc0899afa4622db76ac0. No download/fetch orrevision substitution. Console full command with those exactpaths andcandidateSHA: python -B tests/run_offline.py --tb=line -rs ->447passed,0failed/skipped,24.85s. This supersedes metadata blocker for these recovered verification copies; oldbrokenworktrees untouched.

New pipeline worktree pipeline-audit-fixes, branchfix/combined-audit-remediation basedcandidate893fe1a, preserves exactverificationcopies. Confidence parsing fixed explicitpercentages andbool/nonfinite exclusion;7newcasesfailedbeforefix,26controls passed; final scoring/reporting56passed. Invalidsource parsing now collects bothlexer/parsererrors and rejects beforetreewalk.2invalidcasesfailedbeforefix/1validcontrolpassed. Actual ContractDownloader.run regression withcontrolledsourcefetch verifiesinvalidsource raises andwritesnoJSONcache. No historicalsource/weights/data/paper modified.

Latest full pipeline command in remediationworktree: python -B tests/run_offline_depth.py tests ->323passed,0failed/skipped,18.29s,exit0. This is localofflinecoverage, notallchain/livecorrectness. Remediationbranch uncommitted; consolepin unchanged; no push/merge/deploy. Otherpipelinefindingsremainopen. Kluster unavailable afterallchanges, noverificationclaimed.


## Combined audit remediation continuation — 2026-11-04

Work remains IN PROGRESS. Both supplied F01–F07 and independent pipeline findings are retained; this section updates confirmed fixes, not an all-clear. Local only, no agents, installs, external calls, pushes, merges or deployments. Kluster is unavailable in the exposed tool inventory; no Kluster verification claimed.

| Finding | Current status and evidence boundary |
|---|---|
| Missing RPC result / malformed batch / swallowed fallback | Fixed and offline tested in pipeline-audit-fixes/faultseeker/utils/rpc_provider.py. Missing/duplicate/unknown IDs reject whole chunk before cache publication; explicit null preserved; exhausted fallback raises; timeout propagated. New mocked tests initially 9 failed/3 passed. |
| Stale source attribution, ContractName traversal, unrelated directory deletion | Fixed and offline tested in data_collection/contract_downloader.py. Each address gets an owned TemporaryDirectory; only owned scratch is deleted; single-file metadata sanitized. Two regressions failed before fix. Synthetic explorer response proves path handling, not explorer compromise. Existing historical caches are NOT independently validated or migrated. |
| Same-name adjacent-address source substitution | Fixed and offline tested in function_analysis/function_analyzer.py. Requested address preserved in dict/list/tuple formats; all three regressions failed before fix. No unverified proxy inference. |
| Empty repeated-pattern schema adds confidence / ignores values | Fixed and offline tested in core/confidence_scorer.py. Actual keys/keys_function_only lists consumed. Both regressions failed before fix. No claim that heuristic weights are scientifically calibrated. |
| Malformed calibration vectors and nonfinite features | Fixed and offline tested in research/calibration.py. Validate equal lengths, unique nonempty feature names, finite parameters/features, positive scales and boolean serialized trained flag. Twelve regressions failed before fix; valid round trip retained. No fitted weights, datasets, paper or frozen results changed. Untrained-model inference policy is unchanged. |
| Credential-bearing built-in QuickNode URL | Removed from current pipeline working source, with safe failing-then-passing regression. Credential validity not tested; history still contains it and owner rotation is required. No credential value recorded here. |
| Interaction graph deep recursion / exhaustive simple-cycle materialization | Fixed and offline tested in forensics/interaction_graph.py. Iterative ancestor-aware traversal; cycle enumeration capped at 1000 with explicit lower_bound/truncated metadata, exact small counts retained. Four new regressions failed before fix; 1024 synthetic frames require no recursion-limit adjustment. This is not a hard execution-time bound for arbitrary graphs. |

Latest pipeline command (pipeline-audit-fixes): `python -B tests/run_offline_depth.py tests` -> 369 passed, 0 failed, 0 skipped, 29.16s. Runner blocks network, clears credential environment variables and uses temporary working directories. `git diff --check` passed. Console integration against exact Docker pin fb57c3fad63784b7a63dc7fdf1845364c76ce0b7 and modified remediation tree based on 893fe1a8067c2b2f6fdcbc0899afa4622db76ac0 passed 447 tests before the final graph/credential changes; a follow-up run is in progress. Candidate source is an UNCOMMITTED working tree, not a new verified commit. Frontend command `node tests/run_frontend_offline.cjs` -> 22 passed, 0 failed/skipped, 84.20ms; static-sync check passed.

Remaining confirmed items are NOT labelled fixed: deterministic signal false positives/invented numeric estimates; historical cache provenance; parser overload/special-function limitations; call-depth feature semantics and scorer source-context wiring; fund-flow schema/order; task/checkpoint error propagation; trace root validation/legacy field loss; explorer error failover; human feedback behavior; router/gate policy distinctions; standalone research-tool defects. Maximum-depth-only finalization needs ranking-contract decision before changing behavior. Supplied F05 slow-stream hypothesis remains unverified; F07 is bounded retry policy, not an established infinite retry. Existing console F01/F02/F03/F04/F06 fixes and prior partial-status/provenance changes remain in the console working tree. No live chain correctness passes established by these offline results.

Final follow-up console integration with the same exact-pin path and modified pipeline-audit-fixes candidate path completed: `python -B tests/run_offline.py --tb=line -rs` ->447 passed, 0 failed, 0 skipped, 29.93s. This covers the final graph/credential changes at the existing integration boundaries. Both repositories diff checks and console static-sync check passed. No new commit, live call or deployment.


## Deterministic evidence and task failure follow-through — 2026-11-04

Confirmed fixes in pipeline-audit-fixes (uncommitted):
- forensics/signal_extractor.py: delegatecalls, privileged names, undecoded selectors and cross-contract calls no longer claim authorization bypass. Retain privileged-call/delegation/review observations. Cast selector counts are retained instead of overwritten by an empty structured list. Deposit/transfer/borrow is an inflation-pattern observation, not confirmed inflation.
- Gross call values and unpriced token deltas no longer become ETH profit. Profit and price deltas serialize as null with explicit unavailable measurement status; largest gross call value remains available under its own name. Sequence observations remain, without invented 10%/20% changes. No net-native-profit or measured reserve-change implementation is claimed.
- forensics/rule_classifier.py: ordinary created-contract initialization is UNCERTAIN; newly separated access-control/inflation pattern observations remain unconfirmed. Other rule predictions remain heuristics, not verified exploit probabilities. Reentrancy thresholds/tiers were not silently retuned.
- function_analysis/function_analyzer.py: deterministic prediction no longer seeds cheatsheet as confirmed vulnerability. Model prompt labels deterministic context and prior observations unverified. Findings require a valid object/entry, nonempty evidence and finite 0..1 numeric confidence; zero confidence is preserved. Malformed replies reject atomically. Task errors propagate from both analysis loops even when an earlier candidate exists, allowing console partial/error handling instead of normal-looking completion.
- forensics/result.py: priority computation accepts unavailable price delta without crashing. Existing heuristic weights are unchanged.

Evidence: 11 initial signal/prompt counterexamples failed; created-initializer regression additionally failed before correction; positive observation-preservation control retained. Initial task-integrity run 11 failed/1 passed; focused corrected run across analysis/signal/target modules 35 passed. Synthetic traces and mocked task boundaries, not historical ground truth. Real FunctionAnalyzer.run initialization is covered to the source boundary; no model call or complete transaction verified.

Final command in pipeline-audit-fixes: `python -B tests/run_offline_depth.py tests` ->394 passed,0 failed,0 skipped,15.75s. Console with FAULTSEEKER_TEST_PIPELINE_REPO=pipeline-pin-offline-verified (fb57c3f...), FAULTSEEKER_TEST_CANDIDATE_REPO=pipeline-audit-fixes, FAULTSEEKER_TEST_CANDIDATE_SHA=893fe1a8067c2b2f6fdcbc0899afa4622db76ac0: `python -B tests/run_offline.py --tb=line -rs` ->447 passed,0 failed,0 skipped,20.97s. Candidate working changes remain uncommitted; these are source-working-tree tests, not a new pinned deployment. Diff checks passed. Frontend last unchanged result22 passed/0 failed/skipped. Kluster still unavailable; no Kluster review claimed.

Remaining items still open: historical cache provenance, parser overload/special functions, call-depth calibration feature mismatch, scorer source-context wiring, fund-flow schema/order, iteration/time-cap/empty-task exit policy, root/legacy trace integrity, explorer error failover, human feedback, router/calibration policy and standalone research-tool defects. Model-response schema failure is now propagated, but this does not prove every task/checkpoint exit is covered. Maximum-depth-only finalization is still a design decision. No external calls, branch publication or deployment. Real correctness remains0/16 development and0/16 live.


## Trace identity / failure metadata continuation — 2026-11-04

Previous goal turn made concrete code/test progress; goal remains active, not complete. This cycle confirmed and fixed:
- app/trace_identity.py: equality of two absent sender/calldata values no longer verifies root identity. Required compared fields must be nonempty strings; explicit empty calldata `0x` remains valid. Missing transaction `to` key and non-dict root reject. Seven initial regressions failed/one valid-empty-calldata control passed. This does not claim every field has strict hex-format validation.
- Console canonical_to_legacy now preserves caller, full input, success, return_data and error. Cyclic object traversal rejects with ValueError; shared nodes on distinct paths remain allowed by ancestor-scoped detection. Bounded tripwire regression reproduced the old loop without creating an unbounded test thread.
- Pipeline txn_sequencer._canonical_to_legacy_trace and TraceNode.from_dict/to_dict preserve the same call-failure metadata. Tests cover real sequencer run to its controlled replay/visualization boundaries and actual TraceNode round trip. rpc_provider.normalize_trace_node retains provider error when present. Two converter regressions and one provider error regression failed before correction.
- Console sequence_from_parity now carries error/success/output directly into canonical and legacy trees, removing explorer_trace's later error-reinjection loop. A controlled mutation of the verified historical fixture tests failed-frame handling; it is explicitly NOT evidence that the historical transaction frame failed.

Full pipeline initially found6 frozen-schema test failures after adding error metadata (391passed). Original frozen hashes were NOT changed. Mixed-schema tests explicitly verify the new error fields and compare the original-field projection to the unchanged captured hashes; absent-error payloads retain original schema. This is a documented schema extension, not new historical ground truth or replacement expected hashes.

Final verification:
- pipeline-audit-fixes: `python -B tests/run_offline_depth.py tests` ->397passed,0failed,0skipped,15.40s; `git diff --check` passed.
- FaultSeeker_Live with exact fb57c3fad63784b7a63dc7fdf1845364c76ce0b7 pin and uncommitted remediation candidate based893fe1a8067c2b2f6fdcbc0899afa4622db76ac0: `python -B tests/run_offline.py --tb=line -rs` ->457passed,0failed,0skipped,20.39s. Same FAULTSEEKER_TEST_PIPELINE_REPO/FAULTSEEKER_TEST_CANDIDATE_REPO/FAULTSEEKER_TEST_CANDIDATE_SHA paths as preceding checkpoint.
- `node tests/run_frontend_offline.cjs` ->22passed,0failed,0skipped,74.94ms.
- `python -B tests/browser_checks.py --offline` ->11checks passed, including partial502 report, cancelled result, saved history, storage, XSS-safe evidence, responsive layouts and no uncaught exceptions. Artifacts: C:/Users/91701/AppData/Local/Temp/faultseeker-browser-qa. Synthetic routes/offline capture only, no real-chain completeness claim.
- Static sync and console diff checks passed. Kluster unavailable in tool inventory; no Kluster review claimed. No agent, install, external RPC/model request, GitHub operation, commit, push, merge or deployment.

Remaining: historical cache provenance, parser overload/special-function mapping, calibration call-depth semantics/source context, fund-flow order/schema, other loop/empty-task/time-cap exits, explorer failover, feedback and router/calibration policy, standalone research tools and finalization contract. This fixes the specifically reproduced missing-root and metadata defects, not every possible trace-schema defect or all16-chain validation. Full correctness remains0/16dev and0/16live.


## Source-cache and scoring follow-through — 2026-11-04

Concrete progress this cycle, no external calls or publication. Pipeline branch remains fix/combined-audit-remediation; all changes uncommitted.

| Finding | Updated disposition |
|---|---|
| Legacy/source cache identity and corruption | Fixed and offline tested for request identity/parser schema: cache reads require version2 envelope with matching address/chain, explorer_current source kind and explicit historical_binding=unverified; validate function entry structure. Old bare dictionaries/mismatches/corrupt JSON refetch, no fallback to their contents. Atomic tempfile+replace publication prevents partial cache JSON. Constructor rejects path-like identities and accepts a single address as a one-item list. Seven initial regressions failed; source/parser module final13passed. Wrong-chain/address tests use otherwise valid envelopes; actual fresh-envelope reuse is checked. |
| Historical bytecode/block source binding | Still OPEN, not solved by a cache envelope. Request identity is not cryptographic source provenance. Current explorer source cache is explicitly unverified for historical binding; console verified-ABI/source checks remain necessary. Old user caches were not bulk deleted or relabelled verified. |
| Missing Stage3 source-context wiring / wrong source schema | Fixed and offline tested: pipeline passes analyzer.contract_info to scorer; scorer recognizes target-specific downloader function content as well as legacy whole-source strings. Empty address entries, empty target source or another function do not earn source-availability boost. Weights unchanged; code availability is not proof of vulnerability. |
| Stage3 untrained calibrator applied / hidden calibration failures | Fixed and offline tested: trained flag must be exactlyTrue before applying. Report calibration field distinguishes applied, no_model, no_findings, model_untrained and calibration_failed. Valid zero probabilities remain supported; calibration failure retains all heuristic scores atomically. Existing positive mock explicitly models a trained calibrator, not SDK/model correctness. |
| Calibration call-depth and broader feature semantics | CONFIRMED OPEN: orchestrator call_depth_max uses graph node_count, Stage3 reads signals.call_depth; benchmark/export_research_features.py uses debug.call_depth_max. Static read of benchmark/retrain_calibrator.py confirms its normalize() creates all8 feature columns from4 trace proxies: entropy and call_depth both normalized max_depth; token_flow_anomaly is gas proxy. Shipped model means/scales for entropy and depth are identical. No training script executed, no weights/frozen data/paper modified. Cannot repair this by changing one test pin/key or silently reusing fitted weights under another feature definition. Next work: explicit model feature-contract gating and consistent measured feature definitions before claiming calibrated probabilities. Generic shape/finite/trained validation alone does NOT establish valid calibration. |

Tests: initial source-cache run7failed/6passed; initial scoring/reporting run7failed/58passed. Corrected focused scoring/source run78passed,0failed/skipped. Full pipeline `python -B tests/run_offline_depth.py tests` ->411passed,0failed,0skipped,15.49s. Console same exact-pin/remediation-candidate env configuration as prior checkpoint, `python -B tests/run_offline.py --tb=line -rs` ->457passed,0failed,0skipped,20.30s. After strengthening cache mismatch cases, source module rerun13passed,0failed/skipped,2.23s. Both diff checks passed. Frontend/browser code unchanged; latest prior22frontend/11browser checks remain their stated offline scope. Kluster unavailable; no Kluster review claimed. No live chain correctness pass:0/16dev and0/16live.


## Calibration feature-contract remediation — 2026-11-04

Previous turn made concrete changes/tests; this goal turn also made progress. No agents/external calls/publication. Both working branches retain uncommitted changes.

Confirmed calibration mismatch is now guarded in BOTH runtime scoring paths. research/calibration.py adds declared input_contract serialization, require_runtime_calibrator and runtime_feature_row; generic research inference remains available for reproducing old models. The runtime accepts only trained models with exact ordered features and faultseeker.runtime-components.v1 semantics. Unknown/legacy/proxy contracts reject without prediction. Missing/nonfinite/bool feature values are unavailable, not silentlyzero. Explicit measuredzeros remain valid. No existing model is auto relabelled compatible; git diff --exit-code -- data/models passes.

ForensicsOrchestrator now measures structural trace edge depth iteratively (root0, absentNone), publishes call_depth and call_depth_max consistently, and distinguishes unavailable state/graph context. State feature counts observed storage-write events only when available; graph anomaly remains explicitly a heuristic. Stage1 does not fabricate absent per-function scoring components aszero. It records why calibration is not applied. Stage3 uses the same feature-row contract and preserves all heuristic scores on incompatibility/failure. Full actual orchestrator run with controlled collection/trace/classifier boundaries reproduced node_count4 incorrectly used asdepth; fixed reportsdepth1 for that star tree. Separate1024-frame depth metric test passes without recursion-limit adjustment. This does NOT assert every later pipeline walker handles1024frames.

Operational consequence: the shipped proxy-trained model has no verified runtime contract and will NOT be auto-applied by corrected runtime. Scores stay heuristic and reports expose feature_contract_unverified. We did not train/retrain, alter weights, relabel the old model, edit papers or claim valid calibration. Metadata establishes declared compatibility only; accuracy needs independent real-runtime labelled validation. Contract documented in pipeline-audit-fixes/docs/calibration-feature-contract.md.

UI: confidence-basis panel explicitly labels uncalibrated scores and the recognized reason. Matching declared contract is displayed without claiming independently verified accuracy. Static assets synchronized, JS query version changed to audit-integrity-3. Browser image inspection exposed existing corrupted separator/ellipsis strings;14separator instances and1ellipsis corrected to ASCII, with failing-then-passing visible-text regression. Saved captures retain recorded scope.

Reproductions: initial calibration/depth run4failed/28passed; corrected focus56passed. New UI calibration tests4failed with22controls passing; corrected26passed. Encoding regression1failed/26passed then27passed. These are schema/flow tests, not chain/model correctness.

Final verification:
- pipeline-audit-fixes `python -B tests/run_offline_depth.py tests`:421passed,0failed,0skipped,16.09s.
- FaultSeeker_Live same exact fb57c3f... pin/remediation working candidate env configuration as preceding entries, `python -B tests/run_offline.py --tb=line -rs`:457passed,0failed,0skipped,20.95s.
- `node tests/run_frontend_offline.cjs`:27passed,0failed,0skipped,71.67ms (after final string fixes).
- `python -B tests/browser_checks.py --offline`:12checks passed after final string fixes,8.90s; includes visible heuristic confidence basis, saved history, partial502, cancellation, XSS and responsive checks. Artifacts C:/Users/91701/AppData/Local/Temp/faultseeker-browser-qa; report-mobile.png inspected. Offline fixture/capture only.
- Both diff checks, static sync check and unchanged model-artifact check passed. Kluster unavailable in tool inventory, no review claimed.

Remaining: real compatible calibrator training/validation unavailable (no probability claim); historical source binding; parser overload/special functions; fund-flow schema/order; loop/time/empty-task exits; other trace deep walkers; explorer failover; human feedback; finalization/routing policy and standalone research-tool issues. No live analysis, push, merge or deployment. Correctness remains0/16development and0/16live.


## Fund-flow integrity and explicit incomplete exits — 2026-11-04

Progress: confirmed fixes and regressions executed. No agents, live API/RPC calls, package operations, publication or deployment. Kluster remains unavailable in exposed inventory, no review claimed.

| Finding | Disposition / evidence |
|---|---|
| FundFlowAnalyzer roles persist across run() calls and mutate earlier returned lists | Fixed: reset per-run roles, balances, graph/context; deduplicate and normalize participant addresses. Real run() reuse regression initially failed, corrected first and second outputs remain isolated. |
| Nonfinite/negative/invalid token amounts; silently skipped malformed data | Fixed: explicit validated parsing and errors; local balance assembly publishes only after successful processing. Original NaN/Infinity/negative/non-numeric cases all failed to reject before fix. No successful empty ledger is substituted. |
| Own-token contract outgoing transfer dropped / mixed-case identity split | Fixed with synthetic valid-schema regressions. Removed source==token exclusion, normalize address/asset identity. This does not claim historical explorer events were independently verified. |
| Invalid victim response silently accepted | Fixed: require string address list, filter to observed identities; also support explicit victims JSON envelope for JSON-object providers and legacy list responses. Production prompt no longer presupposes malicious transactions. |
| Float arithmetic loses small transfer beside a large one | Confirmed actual run: 10^20 outgoing then1 incoming produced -1e20. Fixed Decimal arithmetic with bounded parse lengths/exponents and inexact traps; amount serialized as decimal string, not approximate float. Semantic -2/+2 controls unchanged, tests parse the new representation as decimal. This is an intentional wire-type change documented in pipeline-audit-fixes/docs/fund-flow-contract.md; old reports retain old numeric values. Exactness is relative to supplied labels, not proof of raw-log accuracy. |
| SignalExtractor float(delta) mismatch / early role ordering | Original erroneous native-profit consumer was removed in prior fixes. Nested token schema is retained, now exact strings. Trace signals intentionally precede model roles; native profit remains unavailable. No reordering or conversion of token units to ETH introduced. Full historical balance provenance remains open. |
| Substring yes prematurely marks adequacy | Fixed both function/transaction loops: explicit affirmative matches the console guard's strict yes/whitespace/punctuation semantics. No, not yes and Yesterday no longer stop atcycle2. Positive Yes. control still stops. |
| Empty-selection/time-limit normal-looking return | Fixed both loops: AnalysisIncompleteError with kind analysis_incomplete and bounded reason. Time limit prevents a new cycle at>=480s; existing positive response handling is not discarded by this boundary. Existing iteration ceilings unchanged. Loop timing remains wall-clock/between-cycle, not an in-flight interrupt. |
| Candidate error -> console report cross-module contract | Two actual candidate loop + PipelineRuntime integration tests pass: raised incomplete error, wall-cap recorderror, partial status, verdictINCONCLUSIVE, function_analysisfailed, scoringskipped. Controlled prior-stage snapshot only; no real trace/chain correctness claim. |

Reproductions: initial fund-flow12failed; new loop/JSON-envelope run11failed/26passed; precision1failed/15passed. Focused corrected failure/fund-flow40passed. Real FundFlowAnalyzer constructor -> provider factory -> installed OpenAI SDK2.36.0/httpx0.28.1 -> mocked HTTP tests verify native JSON-object request, valid victim envelope and malformed schema rejection with one request each. Dummy credentials, network blocked by runner; these are not live calls or evidence of compatibility with other SDK versions. Module final16cases (including SDK cases) covered by full suite.

Final exact commands/results:
- pipeline-audit-fixes `python -B tests/run_offline_depth.py tests` ->449passed,0failed,0skipped,25.50s.
- Console same exact Docker-pin fb57c3f... plus uncommitted remediation candidate based893fe1a... env setup as prior checkpoint: `python -B tests/run_offline.py --tb=line -rs` ->459passed,0failed,0skipped,31.82s. Newly added candidate incomplete-report tests run against pipeline-audit-fixes, not the untouched candidate snapshot.
- Both git diff checks passed. Frontend unchanged this cycle; last27frontend and12offline-browser checks remain prior executed scope.

Remaining: historical source/log binding, parser overload/special functions, other deep walkers, explorer failover, human feedback and finalization/role-filter/routing policy; independently validated compatible calibrator not available. Additional static prompt observation for follow-through: initial function/transaction task-tree text premarks source retrieval completed even when no source is supplied; model-output impact not yet reproduced. Trace/model errors and malformed finding paths now propagate, but do not call every task/checkpoint exit or source-provenance path verified. All real-chain correctness still0/16development and0/16live.


## Explorer/parser fixes and approved finding policy — 2026-11-04

Concrete progress, not a complete audit or chain validation. No agents, external calls, package operations, commits/push/merge/deploy. Kluster unavailable in tool inventory; no review claimed.

| Finding | Current disposition |
|---|---|
| Explorer NOTOK masks auth/rate/server error in result | Fixed and offline tested. Read status/message/result together; classify known failures with safe static messages; unsuccessful endpoint is penalized and next configured endpoint can be tried once. Known no-records/unverified-source negatives remain healthy API responses. Successful source text is not scanned as an error. Four initial tests failed/two controls passed; module final6passed. No live provider reachability or current API-version support verified. |
| Explorer diagnostic URL/body disclosure | Fixed in module diagnostics: labels contain hostname only, no userinfo/path/query. Unknown exception diagnostics use type only; application failures use static messages, not remote echoed body. Dummy-credential repr/stats/log test failed before fix, passes afterward. Does not establish global secret absence or fix every RPC-module logger. |
| Same-name overload overwrite / special functions omitted | Fixed listener for supported grammar: ordered overload spans retained, constructor/receive/fallback recorded. Exact character spans distinguish definitions sharing a line. Downloader keeps all alternatives, analyzer retrieves both rather than choosing a name-only ABI identity. |
| Single-line source discarded / whole-line source mixing | Fixed downloader extracts exact spans and analyzer accepts single-line definitions, labels plain source binding unverified and same-name source alternatives explicitly. Actual get_loc_info -> ContractDownloader.parse_contract -> FunctionAnalyzer._retrieve_source_code regression passes. Not a historical ABI/bytecode binding or full worker correctness proof. |
| Multi-file flattened paths collide | Fixed with path-derived hash prefix plus sanitized basename. a/b.sol and a_b.sol both survive extraction. No import compilation or source provenance inferred from filename hashing. |
| Reusing old parser-cache results | Fixed cache requires parser_contract=solidity-spans-v1 in addition to existing version/address/chain checks. Old line-only results refetch; existing envelopes are not auto relabelled. Missing historical binding remains unverified. |
| Initial task tree falsely premarks source retrieval completed | Fixed in both function/transaction loops: summary/source presence shown without a false completed claim; missing source remains unavailable, provided source still needs binding review. Four prompt-capture regressions failed before correction. No claim of independently measured effect on historical model output. |
| Valid user-defined value-type declaration unsupported | Confirmed but deferred with exact local dependency limit: actual offline valid Units declaration raises safe unavailable-source ValueError. No .g4 grammar or generator jar found in this repository; Get-Command antlr4 returns no command. Updating generated grammar requires matching grammar/generator not available under no-download/install constraint. No regex substitute, no silent success or skipped integration claim. Scope documented in pipeline-audit-fixes/docs/source-parser-contract.md. |
| Deepest-depth-only finalization | User chose retain all analyzed findings and rank; decision applied. Every candidate retained, omitted model-ranked targets appended, ranking keys validated, duplicates normalized. Depth remains context and no longer boosts heuristic confidence. Exact target names/addresses/evidence retained. Both cloud/local ranking prompts support JSON-object mode; legacy list supported. Policy documented in docs/finding-selection-policy.md. |

Tests: parser initial6failed/13passed, stale-cache regression extended to7failed/13passed before fixes; source/ranker/explorer focus36passed. Final metadata/alignment source/explorer focus26passed. Prompt regressions4failed/24controls passed before fix, corrected combined source/task48passed. New finalization policy tests7failed initially, corrected policy/scoring/task/report focus103passed. Actual Stage3 with controlled upstream boundaries retains both shallow/deep candidates and both evidence cards, ordered by evidence/confidence; these are synthetic schema/flow tests, not chain ground truth.

Latest full results after approved ranking change:
- pipeline-audit-fixes `python -B tests/run_offline_depth.py tests` ->473passed,0failed,0skipped,39.99s.
- FaultSeeker_Live exact Docker pin fb57c3fad63784b7a63dc7fdf1845364c76ce0b7 and uncommitted remediation candidate based893fe1a8067c2b2f6fdcbc0899afa4622db76ac0, same explicit env paths as preceding entries: `python -B tests/run_offline.py --tb=line -rs` ->459passed,0failed,0skipped,43.90s.
- Both diff checks passed. Frontend unchanged in this cycle; last27frontend/12offline-browser checks remain prior evidence, not newly rerun here.

Real-chain status remains0/16development and0/16live. Local port8765 has no listening process at preparation check; old local server is not a currently running validation handle. Existing local launcher file is present; only its function/global names were inspected, no credential value read/output or model request performed. Any next validation must launch the corrected console with FAULTSEEKER_REPO pointing to pipeline-audit-fixes, not the old candidate/temp path, and verify actual binding. Remaining relevant follow-through includes source ABI wall budget counting model idle time, deterministic candidate entry-point compatibility, other deep walkers, feedback/cross-chain reporting, address registry, standalone research integrity and final full finding-status reconciliation. Live site SHA was not rechecked during offline remediation; no live fix claimed.

### 2026-11-05: remaining reentrancy signal traversal boundary

Confirmed at SignalExtractor._check_reentrancy:1,024 synthetic nested frames raised RecursionError under Python's default recursion limit; an ancestor cycle also raised RecursionError rather than a bounded data error. Two regressions failed before implementation; sibling-reuse control passed. This is a direct-library/default-limit failure, not proof the console main path with its higher recursion allowance crashed historically.

The reentrancy walker now processes explicit stack states in the same preorder, preserving storage-owner/root-context/boundary/selector state. Path-local ancestor identities reject cycles with ValueError while permitting reused sibling objects. Scoring coefficients and detection thresholds are unchanged. The unused generic _walk helper was not changed; this fix does not establish every walker is iterative.

Commands/results:python -B tests/run_offline_depth.py tests/test_signal_trace_depth.py tests/test_signal_evidence_integrity.py:16passed,0failed/skipped,8.29s. Full python -B tests/run_offline_depth.py tests:484passed,0failed/skipped,28.32s. Console exact-pin+modified-candidate python -B tests/run_offline.py --tb=line -rs:462passed,0failed/skipped,36.64s. Pipeline diffcheck passed. No new real RPC/model run after this source change; ef4fafd7836d remains evidence for its own recorded source manifest only.

Status update to earlier audit items: candidate no_llm signature/construction mismatch is fixed and tested; actual deterministic console/history flow verified by ef4fafd7836d as recorded in all-chain-ledger.md, not a scored-function pass. Deep signal traversal is now fixed at the stated boundary. Desktop browser connection reset still fails kernel-assets/path-not-found initialization; working Playwright exposes an unauthenticated context, and process inventory found no Chrome/Edge remote-debugging port. Existing signed-in profile was requested by user but cannot be accessed with the current connection. No browser credential extraction, profile copying or credential changes. Account quota and current deployed revisions remain unverified. Kluster discovery exposes no tools.

### Model-loop information flow status (2026-11-05)

Confirmed and fixed offline:FunctionAnalyzer._update_current_understanding ignored newest completed task/result and repeated initialization input. Tests3failed beforefix,32focused passed afterfix,fullpipeline492passed. Current/previous task evidence now reaches the updated-understanding prompt for both cloud aliases. Exactconsolepin/candidate466passed,frontend27passed. Real outcomes afterfix pending run6256ef573489 Mercury;Qwennext. Do not call Mercury null-output fixed:only finite structural diagnostics added,with private-field/malformed-enum mockedHTTP regressions. No limits or success semantics weakened.

Confirmed remaining routing defect:TransactionInfoCollector.get_transaction_link defaults8advertised chains toEthereum explorer; reproduced offline forall16chain names. Affected:fantom,linea,scroll,gnosis,celo,cronos,moonbeam,aurora. Gnosis/Fantom have separate builtinRPCfallbacks;sixothers do not. Traceidentitycrosscheck is independent,so this does not invalidate recorded chain-bound traces; metadata and overall analysis coverage remain limited. Fix pending; no live source edited midrun.
