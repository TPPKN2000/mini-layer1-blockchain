# Lab 01 – Layer 1 BFT tối thiểu trên mạng mô phỏng không tin cậy

Một discrete-event simulator của `n` validator đạt **finality** bằng giao thức hai pha kiểu Tendermint
(PREVOTE / PRECOMMIT, locking, round timeout) trên một network làm trễ, đảo thứ tự, nhân bản và
làm mất message trước GST.

## Yêu cầu
* Python >= 3.9 (đã thử trên 3.12)
* `pip install cryptography`   (chỉ dùng cho Ed25519; phần còn lại dùng thư viện chuẩn)

Không cần bước build.

## Cấu trúc
```
src/run.py              CLI: chạy một kịch bản và ghi logs/<name>.log
src/minichain/
  encoding.py           canonical byte encoding (hash/chữ ký đều tính trên đầu ra này)
  crypto.py             Ed25519 + domain separation (TX/HEADER/VOTE:chain_id), SHA-256, Merkle
  types.py              Tx, Proposal (header có chữ ký), Vote, block hash
  state.py              key-value state, luật ownership + nonce, Merkle state commitment
  network.py            event queue, delay/dup/drop, giới hạn gửi, chặn peer ở phía nhận, topology
  node.py               Node trung thực (gossip, guard, consensus, sync) + ByzNode (các hành vi lỗi)
  context.py            config mặc định, khóa, log writer, global safety auditor
  simulator.py          dựng kịch bản, workload, tổng kết kết quả
config/T1..T8_*.json    mỗi bài test bắt buộc một kịch bản
tests/                  unit test, end-to-end test T1..T8, determinism checker, entry point duy nhất
logs/                   log do các kịch bản sinh ra
```

## Chạy một kịch bản
```
python3 src/run.py config/T1_normal.json              # ghi logs/T1_normal.log
python3 src/run.py config/T7_byzantine_f.json --seed 42
```
Dòng cuối của mỗi log là một bản tóm tắt JSON (đã finish chưa, vi phạm safety, final state hash,
head của từng node). Exit code là 0 khi và chỉ khi mọi node đúng đạt `target_height` và không có vi phạm safety.

## Chạy toàn bộ test (entry point duy nhất)
```
python3 tests/run_all.py            # unit + end-to-end (T1..T8) + robustness
python3 tests/run_all.py unit       # chỉ unit test
python3 tests/run_all.py e2e        # chỉ T1..T8
python3 tests/run_all.py robust     # test audit deadlock / starvation
```
Kiểm tra determinism (T8) thủ công: chạy kịch bản hai lần ở hai tiến trình riêng với
`PYTHONHASHSEED` khác nhau, rồi so sánh từng byte của log và final state hash:
```
python3 tests/check_determinism.py T8_determinism
```

| Test | Config | Nội dung kiểm tra |
|------|--------|-------------------|
| T1 | T1_normal | cả 10 node finalize cùng chain và state hash, không có timeout |
| T2 | T2_dup_reorder | 30 % duplicate, delay rộng, một node replay dồn dập: không đếm đôi vote, node flood bị block |
| T3 | T3_bad_signature | chữ ký hỏng, sai domain, vote giả danh, key không sở hữu: bị từ chối, log lý do |
| T4 | T4_replay_tx | giao dịch bị replay trước và sau finalize chỉ được áp dụng tối đa một lần |
| T5 | T5_drop_delay_pre_gst | mất 35 %, delay dài trước GST: không finalize mâu thuẫn, có liveness sau GST |
| T6 | T6_silent_proposer | proposer im lặng + một node crash: timeout, sang round kế, chain tiếp tục |
| T7 | T7_byzantine_f | f = 3 node lỗi (proposer/vote equivocate, state hash sai, giả chữ ký) |
| T8 | T8_determinism | cùng seed chạy hai lần: log giống từng byte, cùng final state hash |

## Cấu hình (JSON, được merge lên giá trị mặc định trong `context.py`)
`n` validator (`f=(n-1)//3`, quorum `(n+f)//2+1`, bằng `2f+1` khi `n=3f+1`; mặc định `n=10, f=3`),
`seed`, `target_height`, `network` (topology, delay, `gst_ms`, mất/nhân bản trước GST, giới hạn tốc độ),
`consensus` (timeout), `workload` (giao dịch + lỗi được chèn vào), `byzantine`
(`{"3": ["equivocate","replay"]}`; các hành vi: `silent`, `equivocate`, `invalid_proposal`,
`bad_sig`, `replay`) và `crash` (`{"2": 800}` = node 2 crash lúc 800 ms).

## Determinism
Thời gian là ảo (ms nguyên). Toàn bộ tính ngẫu nhiên lấy từ một `random.Random(seed)` được tiêu thụ theo
thứ tự sự kiện cố định; khóa sinh từ seed; chữ ký Ed25519 là xác định; không có phép duyệt container
không có thứ tự nào ảnh hưởng đến đầu ra. Chạy lại cho log giống nhau từng byte.
