## Abort criteria (즉시 중단 조건)
- 시스템 장애(서비스 중단) 발생
- 비인가 데이터 노출(개인정보/비밀자료 유출 의심)
- 네트워크 과다 트래픽으로 인한 인프라 영향
- IDS/IPS에서 심각한 알람 발생(정책에 따라)

## Immediate actions
1. 즉시 테스트 중지(명령 중단)
2. 네트워크 접속 분리(해당 호스트 isolate)
3. 담당자(운영/네트워크/보안)와 즉시 통화
4. VM 스냅샷에서 즉시 복원(또는 백업 이미지 복원)
5. 증적(PCAP, 로그) 저장 및 무결성 확보
6. 사고보고서 작성 및 후속 대책 실행

## 롤백 예시 (VM 기준)
- VBoxManage snapshot <vm> restore "pre-test"
- 또는 vSphere/Proxmox에서 스냅샷 되돌리기
