# 사이드카 기반 API 보안 게이트웨이 (Sidecar API Security Gateway)

이 프로젝트는 마이크로서비스 아키텍처(MSA) 및 컨테이너 환경에서 애플리케이션 서비스를 안전하게 보호하기 위한 **사이드카(Sidecar) 기반 API 보안 게이트웨이**의 통합 프로토타입 패키지입니다. 

로컬 Kubernetes 환경에서의 컨테이너 가동은 물론, 멀티 프로세스 번들 기법을 이용한 클라우드 PaaS(Vercel & Railway) 배포 가이드를 모두 제공합니다.

---

## 🛠️ 주요 아키텍처 및 구성 요소
1. **Envoy Proxy (사이드카)**: 인바운드 API 트래픽을 가로채고(Interception) OPA에 실시간 보안 검증을 의뢰합니다.
2. **Open Policy Agent (OPA, 사이드카)**: JWT 서명 여부 검사, IP 블랙리스트 필터링, 그리고 초당 요청 차단을 포함한 상태 없는(Stateless) 인가 처리를 담당합니다.
3. **Target Microservice (FastAPI)**: Envoy 우회를 원천 차단하기 위해 `127.0.0.1:8080` 루프백 인터페이스로 안전하게 격리 바인딩된 모의 이커머스 백엔드입니다.
4. **Log Forwarder (사이드카)**: Envoy 프록시가 남기는 실시간 L7 액세스 로그를 탐지하여 비동기식으로 제어 플레인에 전송합니다.
5. **Control Plane (FastAPI)**: 전송받은 요청 로그를 분석하여 비정상 흐름(Sequence Violation, API 우회 공격) 및 디도스 시나리오를 감지하여 IP를 Redis 블랙리스트에 등록하고 OPA 정책 번들(`.tar.gz`)을 즉시 재컴파일 및 핫 릴리즈(Hot Release)합니다.
6. **Redis**: 제어 플레인의 세션 이력 상태 및 IP별 실시간 트래픽 상태를 유지하기 위한 인메모리 저장소입니다.
7. **Sidecar Security Console**: 수집된 실시간 메트릭 통계(Active Blocks, Event Counter), 차단된 IP 목록(개별 차단 해제 기능 탑재), 그리고 라이브 HTTP 프록시 트래픽 상태를 한눈에 볼 수 있도록 자체 서빙되는 관제용 대시보드 웹 서비스입니다.

---

## 📂 디렉토리 구조
```text
/sidecar-security-gateway
├── apps/
│   └── target-app/          # 타겟 마이크로서비스 애플리케이션 및 로컬 Dockerfile
├── control-plane/           # 제어 플레인 소스 코드, OPA 정책 자동 컴파일 엔진
├── envoy/                   # Envoy static 프록시 라우팅 설정 파일
├── opa/                     # OPA 엔진 폴링 동기화 구성 설정 파일
├── log-forwarder/           # Envoy 로그 테일링 및 전송 포워딩 에이전트
├── frontend/                # Vercel 배포용 단독 정적 웹 콘솔 소스 (API 엔드포인트 수동 입력기 포함)
├── k8s/                     # Kubernetes 배포 및 설정 매니페스트 파일들
│   ├── envoy-config.yaml    # Envoy 설정 및 admin(:19000) 노출 ConfigMap
│   ├── opa-config.yaml      # OPA ConfigMap
│   ├── redis.yaml           # Redis Deployment & Service
│   ├── control-plane.yaml   # 제어 플레인 Deployment & Service (NodePort 30090)
│   ├── prometheus.yaml      # 프로메테우스 메트릭 수집 엔진
│   ├── grafana.yaml         # 그라파나 시각화 대시보드 (NodePort 30300)
│   ├── supervisord.conf     # 클라우드 단일 컨테이너용 프로세스 매니저 설정
│   └── target-service-pod.yaml  # 사이드카 및 메트릭 포트를 포함한 핵심 타겟 Pod 명세
├── Dockerfile.railway       # 클라우드(Railway) 배포용 단일 이미지 다단계 빌드 명세
├── railway.json             # Railway 배포 설정 파일
├── verify.py                # 다양한 시나리오(인증 통과, 비인가 차단, 디도스, 시퀀스 이상) 테스트 스크립트
└── README.md                # 실행 및 운영 가이드 (본 문서)
```

---

## 🚀 1. 로컬 Kubernetes 환경 빌드 및 가동 (Docker Desktop / Kind)

### 필수 요구사항
* Docker 데몬이 실행 중이어야 합니다.
* 로컬 Kubernetes 클러스터 (`Kind`, `Minikube`, 혹은 `Docker Desktop K8s`)가 가동 중이어야 합니다.
* `kubectl` 및 `python3`가 로컬에 설치되어 있어야 합니다.

### 1단계: 도커 이미지 빌드 및 클러스터 로딩 (Kind 기준)
```bash
# 로컬에서 게이트웨이 도커 이미지 빌드
docker build -t target-app:latest ./apps/target-app
docker build -t control-plane:latest ./control-plane
docker build -t log-forwarder:latest ./log-forwarder

# Kind 클러스터 안으로 이미지 로드
kind load docker-image target-app:latest
kind load docker-image control-plane:latest
kind load docker-image log-forwarder:latest
```

### 2단계: 설정 파일 및 쿠버네티스 서비스 배포
```bash
# ConfigMap 리소스 적용
kubectl apply -f ./k8s/envoy-config.yaml
kubectl apply -f ./k8s/opa-config.yaml

# Redis 및 모니터링 컴포넌트 배포
kubectl apply -f ./k8s/redis.yaml
kubectl apply -f ./k8s/prometheus.yaml
kubectl apply -f ./k8s/grafana.yaml

# 제어 플레인 및 타겟 서비스 Pod 배포
kubectl apply -f ./k8s/control-plane.yaml
kubectl apply -f ./k8s/target-service-pod.yaml
```

모든 Pod의 Ready 상태가 `Running`이 될 때까지 대기합니다:
```bash
kubectl get pods
```

### 3단계: 로컬 포트 포워딩 (Port Forwarding)
클러스터 내부의 트래픽을 로컬 호스트로 개방합니다. 별도의 터미널 창을 여러 개 열어 각각 아래 명령을 유지해 주십시오.

```bash
# 1. API 게이트웨이 인그레스 포트 포워딩
kubectl port-forward svc/gateway-service 8000:8000 --address=0.0.0.0

# 2. 통합 보안 관제 웹 콘솔 포트 포워딩
kubectl port-forward svc/control-plane-service 8090:8090 --address=0.0.0.0

# 3. 그라파나 대시보드 포트 포워딩
kubectl port-forward svc/grafana-service 3000:3000 --address=0.0.0.0
```

---

## ☁️ 2. 클라우드 환경 배포 가이드 (Vercel & Railway)

### Vercel 배포 (프론트엔드 관제 대시보드)
Vercel CLI를 사용해 단독 정적 웹 콘솔을 즉시 프로덕션 환경에 배포합니다:
```bash
cd frontend
npx vercel --prod --yes
```
* 배포가 완료되면 발급받은 도메인으로 접속하여, 우측 상단 입력 칸에 **Railway에 배포된 Control Plane의 공인 URL**을 주입하여 연동합니다.

### Railway 배포 (백엔드 및 인프라)
1. **GitHub 리포지토리 연동**:
   * 본인의 GitHub에 해당 프로젝트를 푸시하고 Railway 서비스 대시보드에서 `control-plane` 및 `gateway-service` 서비스를 생성하여 GitHub을 연결합니다.
2. **빌드 디렉토리/경로 설정 (중요)**:
   * **`control-plane` 서비스** $\rightarrow$ **Settings** $\rightarrow$ **Root Directory**를 `control-plane`으로 설정합니다.
   * **`gateway-service` 서비스** $\rightarrow$ **Settings** $\rightarrow$ **Dockerfile Path**를 `Dockerfile.railway`로 설정합니다.
3. **도메인 발급 및 환경 변수 설정**:
   * `control-plane` 서비스 Settings에서 **Generate Domain**을 눌러 도메인 주소를 얻습니다.
   * `gateway-service` 서비스 Variables 탭에 `CONTROL_PLANE_URL` 이름으로 변수를 추가하고, 값으로 `https://<control-plane-도메인>/logs`를 기입합니다.

---

## 🔍 모의 시나리오 검증 테스트

로컬 포트 포워딩이 유지된 상태(게이트웨이 포트 `8000`)에서 검증 자동화 스크립트를 작동시킵니다:

```bash
python verify.py http://localhost:8000
```

### 테스트 검증 시나리오 동작
* **Scenario 1 (Public Endpoint)**: `/` 및 `/products`와 같은 공개 엔드포인트는 비인가 대상도 제한 없이 접근(200 OK)이 가능합니다.
* **Scenario 2 (Unauthorized Checkout)**: 회원 전용 경로인 `/checkout`에 JWT 서명 토큰 없이 접근 시 Envoy 프록시가 OPA 인가 결과를 바탕으로 즉각 차단(403 Forbidden)합니다.
* **Scenario 3 (Normal Flow)**: 정상적인 접근 경로(홈 $\rightarrow$ 제품조회 $\rightarrow$ 장바구니 담기 $\rightarrow$ 결제)를 밟은 JWT 소지 고객은 정상 결제 처리(200 OK)됩니다.
* **Scenario 4 (Rate Limiting)**: 단시간 내에 게이트웨이에 수십 차례 이상 도배식 공격 요청을 시도하면 비동기 분석기가 즉각 감지하여 실시간으로 IP를 차단 목록에 올립니다.
* **Scenario 5 (Sequence Abuse)**: 메인 페이지나 장바구니 단계를 건너뛰고 결제 페이지로 무작위 직격하는 악성 봇 행위가 2회 이상 감지되면 즉각 블랙리스트에 등재되어 모든 접근이 봉쇄됩니다.
