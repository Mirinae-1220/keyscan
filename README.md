# keyscan

git 레포의 파일과 커밋 기록에서 비밀값(API 키, 봇 토큰, 개인키)과 한국 개인정보를 찾는 Rust CLI다.
커밋 전에 막고, 찾은 키를 어디서 폐기하고 재발급하는지 함께 출력한다.

## 지금 상태 (2026-11-24, 9c047fd)

- 명령 4개: `scan`, `staged`, `history`, `install-hook`
- 기본 규칙 16개(정규식)와 엔트로피 검사 1개. 그중 `kr-phone`은 기본으로 꺼져 있다
- 출력 형식 3개: `text`, `json`, `sarif`
- 테스트 42개(단위 27, 통합 15). Ubuntu와 Windows CI에서 fmt, clippy, test, 자기 검사를 돌린다
- v0.1.0을 GitHub 릴리스(실행 파일 4종)와 crates.io에 올렸다

## 한계와 주의점

- 규칙에 있는 형식과 엔트로피 기준을 넘는 값만 잡는다. 모든 비밀값을 잡지 못한다
- 인코딩되거나 여러 줄에 나뉜 비밀값은 잡지 못한다
- 찾은 키가 실제로 쓰이는지 서비스에 보내 확인하지 않는다. 남의 키를 검증하는 데 악용될 수 있어서다
- 찾은 값은 출력 어디에도 그대로 쓰지 않는다. 비밀값은 앞 4자, 개인정보는 앞 2자만 남긴다
- 엔트로피 검사
  - 키 이름에 `key`, `secret`, `token`, `password`, `pwd`, `auth`, `credential`이 들어간 대입문의 20자 이상 값만 본다
  - 16진수 값은 기준 3.5를 쓴다. 무작위 16진수 20자는 약 21%, 32자는 약 80%만 기준을 넘는다
  - 영문과 숫자가 섞이지 않은 값, 식별자처럼 생긴 값(`ToStage02_JumpAttack`)은 건너뛴다. 숫자 없는 비밀번호는 놓친다
  - 게임 데이터 레포(파일 297,238개)에서 오탐이 19건 남는다
  - `*.lock`, `package-lock.json`, `pnpm-lock.yaml`, `go.sum`, `*.min.js`, `*.min.css`, `*.map`, `*.svg`는 검사하지 않는다
- 한국 서비스 키
  - 카카오 앱 키는 같은 줄에 `kakao`가 있을 때만, 네이버 Client Secret은 같은 줄에 `naver`와 `secret` 대입이 있을 때만 잡는다
  - 카카오와 네이버 키의 길이와 문자 구성은 공식 문서에서 확인하지 못했다. 알려진 형식(카카오 32자리 16진수, 네이버 영문·숫자 8~20자)으로 정했다
  - 토스페이먼츠는 시크릿 키(`live_sk_`, `test_sk_`, `live_gsk_`, `test_gsk_`)만 잡는다. 클라이언트 키(`_ck_`)는 브라우저에 노출되는 값이라 잡지 않는다
- 개인정보
  - 주민등록번호는 2020년 10월 이후 발급분에 옛 검증 공식이 맞지 않아, 생년월일이 실제 날짜인지와 성별 자리만 본다. 날짜처럼 생긴 `6자리-7자리` 숫자는 오탐이 날 수 있다
  - 성별 자리는 1~8만 받는다. 외국인등록번호(5~8)도 같이 잡힌다
  - 구분자 없는 16자리 카드번호는 같은 줄에 `card`, `카드`, `credit`, `결제`가 있을 때만 잡는다. 16자리 숫자는 약 10%가 우연히 Luhn 검사를 통과해서다
  - 휴대폰 번호는 오탐이 많아 기본으로 꺼져 있다
- `scan`은 git이 관리하는 파일과, 아직 `git add` 하지 않았지만 `.gitignore`에 없는 새 파일을 본다. `.gitignore`에 든 파일(예: `.env`)은 보지 않는다
- 기록에서 비밀값을 지워도 이미 복제된 사본에는 남는다. 찾은 키는 재발급해야 한다. keyscan은 커밋 기록을 고치지 않는다
- `install-hook`은 기존 pre-commit 훅이 있으면 덮어쓰지 않고 오류로 끝난다. 기존 훅에 `keyscan staged` 줄을 직접 추가한다
- 훅 스크립트는 `keyscan`을 PATH에서 찾는다. PATH에 없으면 커밋이 실패한다

## 주요 결정

- 규칙은 코드가 아니라 [`src/rules.toml`](src/rules.toml)에 둔다. 규칙마다 형식을 확인한 날짜(`checked`)를 적는다
- git은 `git2` 크레이트 대신 `git` 명령을 실행해 쓴다
- 세 검사 명령은 줄을 모으는 방법만 다르고 같은 검사기와 출력을 쓴다
- 엔트로피 기준은 `min(4.5, 0.85 × log2(길이))`다. 길이 n인 문자열의 엔트로피는 log2(n)을 넘지 못해, 고정 기준 4.5로는 무작위 키 20자를 하나도, 32자를 약 67%만 잡았다
- 한 줄에서 규칙이 하나라도 걸리면 그 줄에는 엔트로피 검사를 하지 않는다
- 테스트의 가짜 토큰과 개인정보는 실행할 때 조립한다. 소스에 완성된 값이 없어 자기 검사와 GitHub 푸시 보호에 걸리지 않는다

## 구성

```
src/main.rs       명령과 옵션, 종료 코드
src/source.rs     scan / staged / history 줄 모으기, 파일 검사 병렬화
src/rules.rs      규칙과 설정 파일 읽기
src/rules.toml    기본 규칙
src/detect.rs     줄 하나 검사
src/entropy.rs    엔트로피 검사
src/validate.rs   Luhn, 사업자등록번호, 주민등록번호 날짜 검증
src/finding.rs    결과와 값 가리기
src/skip.rs       .keyscanignore
src/report.rs     text / json / sarif 출력
src/hook.rs       pre-commit 훅 설치
tests/cli.rs      임시 git 레포를 만드는 통합 테스트
```

## 설치와 실행

필요한 것

- git
- crates.io로 설치할 때만 Rust 1.88 이상(stable)
- Windows 11과 Ubuntu에서 테스트했다. macOS 실행 파일은 빌드만 했고 돌려 보지 않았다

### 0. 설치

실행 파일: [릴리스](https://github.com/Mirinae-1220/keyscan/releases/latest)에서 OS에 맞는 파일을 받아 압축을 풀고 PATH에 둔다.

- Windows x64: `x86_64-pc-windows-msvc.zip`
- Linux x64: `x86_64-unknown-linux-musl.tar.gz`
- macOS Apple Silicon: `aarch64-apple-darwin.tar.gz`
- macOS Intel: `x86_64-apple-darwin.tar.gz`

crates.io:

```sh
cargo install keyscan
```

### 1. 커밋 전에 막기

```sh
cd 내-레포
keyscan install-hook
```

커밋할 때마다 이번 커밋에서 새로 추가된 줄만 검사하고, 찾으면 커밋을 막는다. 훅 없이 직접 돌려도 된다.

```sh
git add .
keyscan staged
```

### 2. 레포 전체와 커밋 기록 검사

```sh
keyscan scan            # 현재 폴더
keyscan scan 경로       # git 레포가 아니면 숨김 파일까지 폴더 전체
keyscan history         # 모든 브랜치의 커밋 기록
```

출력 예시

```
[high] discord-bot-token  디스코드 봇 토큰
  .env:1          MTQw****
  src/bot.py:12   MTU0****
  해결: Discord Developer Portal > Applications > 해당 앱 > Bot에서 Reset Token으로 재발급

2건 발견 (파일 48개 검사)
```

### 3. 옵션

- `--format text|json|sarif`: 출력 형식. 기본 `text`
- `--config <파일>`: 설정 파일. 기본은 레포 최상위의 `.keyscan.toml`(있을 때만)
- `--no-entropy`: 엔트로피 검사 끄기
- `--min-severity high|medium|low`: 이 위험도 이상만 보고. 기본 `low`

종료 코드

- `0`: 찾은 것 없음
- `1`: 하나 이상 찾음
- `2`: 실행 오류(git 없음, 설정 파일 오류, 읽지 못한 파일). 찾은 것이 있으면 다른 오류가 있어도 `1`

### 4. 설정과 무시

`.keyscan.toml`

```toml
disable = ["discord-webhook"]   # 기본 규칙 끄기
enable = ["kr-phone"]           # 기본으로 꺼진 규칙 켜기

[entropy]
base64 = 4.5                    # 40자 이상 값의 기준
hex = 3.5

[[rule]]
id = "corp-api-key"
name = "사내 API 키"
regex = '\b(?P<secret>[0-9a-f]{40})\b'   # secret 그룹만 가려서 보여 준다
keywords = ["corp"]                        # 같은 줄에 있을 때만 검사(대소문자 무시)
severity = "high"                          # high | medium | low
fix = "사내 키 관리 화면에서 재발급"
# validate = "luhn" | "kr-brn" | "kr-rrn", keep = 남길 앞 글자 수(기본 4)
```

- `.keyscanignore`: 레포 최상위에 두고 `.gitignore` 문법으로 무시할 경로를 적는다
- 줄 끝에 `keyscan:allow`를 적으면 그 줄만 무시한다

### 5. GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- run: cargo install keyscan
- run: keyscan scan
```

SARIF로 GitHub 보안 탭에 올리려면 다음과 같이 한다.

```yaml
- run: keyscan scan --format sarif > keyscan.sarif || true
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: keyscan.sarif
```

### 6. 테스트

```sh
cargo test        # 42개
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
