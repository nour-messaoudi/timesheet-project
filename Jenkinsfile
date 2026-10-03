import groovy.transform.Field

// ====================================================================
// SUIVI DES STAGES (alimente le rapport DevSecOps)
// ====================================================================

@Field Map STAGE_STATUS   = [:]
@Field Map STAGE_DURATION = [:]
@Field Map STAGE_INFO     = [:]

// Exécute le corps d'un stage en enregistrant son statut et sa durée
def runStage(String name, Closure body) {
    long t0 = System.currentTimeMillis()
    STAGE_STATUS[name] = 'RUNNING'
    try {
        body()
        STAGE_STATUS[name] = 'SUCCESS'
    } catch (err) {
        STAGE_STATUS[name] = 'FAILED'
        throw err
    } finally {
        STAGE_DURATION[name] = System.currentTimeMillis() - t0   // en ms
    }
}

// Écrit les fichiers d'entrée du rapport (stages.txt + meta.txt)
def writeReportInputs() {
    def lines = []
    for (String k : STAGE_STATUS.keySet()) {
        lines << "${k}|${STAGE_STATUS[k]}|${STAGE_DURATION[k] ?: 0}"
    }
    writeFile file: "${env.REPORTS_DIR}/stages.txt", text: lines.join('\n') + '\n'
    writeFile file: "${env.REPORTS_DIR}/meta.txt", text: """result=${currentBuild.currentResult}
qualityGate=${STAGE_INFO['qualityGate'] ?: 'N/A'}
sonarUrl=${STAGE_INFO['sonarUrl'] ?: ''}
sonarKey=${env.SONAR_PROJECT_KEY}
image=${env.DOCKER_IMAGE}
"""
}

pipeline {

    agent any

    // ============================================================
    // OPTIONS
    // ============================================================

    options {
        skipDefaultCheckout(true)          // évite le double checkout
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 60, unit: 'MINUTES')
    }

    // ============================================================
    // ENVIRONMENT
    // ============================================================

    environment {

        // Docker
        DOCKER_REPOSITORY = 'nouuur/timesheet'
        DOCKER_IMAGE      = "${DOCKER_REPOSITORY}:${BUILD_NUMBER}"

        // Kubernetes
        K8S_NAMESPACE     = 'timesheet-platform'
        APP_SERVICE       = 'timesheet'      // nom du Service k8s de l'app
        PROM_SERVICE      = 'prometheus'     // nom du Service k8s de Prometheus

        // Application
        APP_PORT          = '8082'           // port du Service k8s
        APP_CONTEXT_PATH  = '/timesheet-devops'

        // Ports locaux utilisés par kubectl port-forward
        LOCAL_APP_PORT    = '18082'
        LOCAL_PROM_PORT   = '29090'          // port dédié au pipeline (19090 reste libre pour vos tests manuels)

        // SonarQube
        SONAR_PROJECT_KEY = 'tn.esprit.spring.services:timesheet-devops'

        // Notification e-mail
        NOTIFY_EMAIL      = 'nourmess232@gmail.com'

        // DevSecOps
        REPORTS_DIR       = 'reports'
        TRIVY_TIMEOUT     = '20m'

        // PRODUCTION / OPERATIONS (outils de sécurité à l'exécution)
        KUBESCAPE_THRESHOLD = '60'           // score de conformité minimal (%) NSA/MITRE
        LYNIS_MIN_SCORE     = '50'           // Hardening Index minimal (/100)
        FALCO_NAMESPACE     = 'falco'
        TRIVY_OP_NAMESPACE  = 'trivy-system'
        GRAFANA_SERVICE     = 'grafana'
    }

    stages {

        // ============================================================
        // 1. TOOL CHECK
        // ============================================================

        stage('TOOL CHECK') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e
                            echo "============ TOOL CHECK ============"
                            java -version
                            mvn -version
                            docker --version
                            kubectl version --client
                            trivy --version
                            git --version
                            pre-commit --version
                            python3 --version
                            curl --version | head -1
                            kubescape version
                            lynis show version
                            echo "All required tools are available."
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 2. CHECKOUT FROM GITHUB
        // ============================================================

        stage('CHECKOUT FROM GITHUB') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: '*/master']],
                            userRemoteConfigs: [[
                                url: 'https://github.com/nour-messaoudi/timesheet-project.git',
                                credentialsId: 'github-token'
                            ]],
                            extensions: [[$class: 'CleanBeforeCheckout']]
                        ])

                        sh '''
                            set -e
                            echo "Commit : $(git log -1 --oneline)"
                            mkdir -p "${REPORTS_DIR}"
                            chmod 777 "${REPORTS_DIR}"
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 3. SECRET SECURITY SCAN  (shift-left : avant le build)
        // ============================================================

        stage('SECRET SECURITY SCAN') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            echo "============ SECRET SECURITY SCAN ============"
                            rc=0
                            pre-commit run --all-files > "${REPORTS_DIR}/secret-scan.txt" 2>&1 || rc=$?
                            cat "${REPORTS_DIR}/secret-scan.txt"
                            exit $rc
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 4. CLEAN PROJECT
        // ============================================================

        stage('CLEAN PROJECT') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh 'mvn -B clean'
                    }
                }
            }
        }

        // ============================================================
        // 5. BUILD ARTIFACT
        // ============================================================

        stage('BUILD ARTIFACT') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e
                            mvn -B package -DskipTests
                            ls -lh target/*.jar
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 6. UNIT & SECURITY TESTS  (+ rapport de couverture JaCoCo)
        // ============================================================

        stage('UNIT & SECURITY TESTS') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh 'mvn -B test jacoco:report'
                    }
                }
            }
            post {
                always {
                    junit(
                        testResults: 'target/surefire-reports/*.xml',
                        allowEmptyResults: false
                    )
                }
            }
        }

        // ============================================================
        // 7. SAST - SONARQUBE
        // ============================================================

        stage('SAST - SONARQUBE') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        withSonarQubeEnv('SonarQube') {
                            STAGE_INFO['sonarUrl'] = env.SONAR_HOST_URL
                            withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                                sh '''
                                    set -e
                                    mvn -B sonar:sonar \
                                        -Dsonar.token="${SONAR_TOKEN}" \
                                        -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
                                '''
                            }
                        }
                    }
                }
            }
        }

        // ============================================================
        // 8. QUALITY GATE  (nécessite le webhook SonarQube -> Jenkins)
        // ============================================================

        stage('QUALITY GATE') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        def qg = null
                        timeout(time: 5, unit: 'MINUTES') {
                            qg = waitForQualityGate(abortPipeline: false)
                        }
                        STAGE_INFO['qualityGate'] = qg.status
                        echo "Quality Gate : ${qg.status}"

                        // Mesures SonarQube pour le rapport (non bloquant)
                        withSonarQubeEnv('SonarQube') {
                            withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                                sh '''
                                    OUT="${REPORTS_DIR}/sonar-measures.json"
                                    API="${SONAR_HOST_URL}/api/measures/component"
                                    curl -fsS -G -u "${SONAR_TOKEN}:" "$API" \
                                        --data-urlencode "component=${SONAR_PROJECT_KEY}" \
                                        --data-urlencode "metricKeys=software_quality_reliability_issues,software_quality_security_issues,software_quality_maintainability_issues,security_hotspots,coverage,duplicated_lines_density,ncloc" \
                                        -o "$OUT" \
                                    || curl -fsS -G -u "${SONAR_TOKEN}:" "$API" \
                                        --data-urlencode "component=${SONAR_PROJECT_KEY}" \
                                        --data-urlencode "metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density,ncloc" \
                                        -o "$OUT" \
                                    || echo "Mesures SonarQube non recuperees (non bloquant)"
                                '''
                            }
                        }

                        if (qg.status != 'OK') {
                            error "Quality Gate SonarQube en echec : ${qg.status}"
                        }
                    }
                }
            }
        }

        // ============================================================
        // 9. SCA - DEPENDENCIES SCAN (Trivy fs sur pom.xml)
        // ============================================================

        stage('SCA - DEPENDENCIES SCAN') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e
                            trivy fs \
                                --scanners vuln \
                                --severity HIGH,CRITICAL \
                                --timeout "${TRIVY_TIMEOUT}" \
                                --exit-code 0 \
                                --format json \
                                --output "${REPORTS_DIR}/trivy-sca.json" \
                                .
                            trivy convert --format table \
                                --output "${REPORTS_DIR}/trivy-sca.txt" \
                                "${REPORTS_DIR}/trivy-sca.json" \
                            || echo "(conversion table impossible)"
                            cat "${REPORTS_DIR}/trivy-sca.txt" 2>/dev/null || true
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 10. IaC SCAN (Dockerfile + manifests k8s)
        // ============================================================

        stage('IaC SECURITY SCAN') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e
                            trivy config \
                                --severity HIGH,CRITICAL \
                                --exit-code 0 \
                                --format json \
                                --output "${REPORTS_DIR}/trivy-iac.json" \
                                .
                            trivy convert --format table \
                                --output "${REPORTS_DIR}/trivy-iac.txt" \
                                "${REPORTS_DIR}/trivy-iac.json" \
                            || echo "(conversion table impossible)"
                            cat "${REPORTS_DIR}/trivy-iac.txt" 2>/dev/null || true
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 11. PUBLISH / ARCHIVE ARTIFACT
        // ============================================================

        stage('PUBLISH/ARCHIVE ARTIFACT') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        archiveArtifacts(artifacts: 'target/*.jar', fingerprint: true)
                    }
                }
            }
        }

        // ============================================================
        // 12. BUILD DOCKER IMAGE
        // ============================================================

        stage('BUILD DOCKER IMAGE') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e
                            docker build -t "${DOCKER_IMAGE}" .
                            docker images "${DOCKER_REPOSITORY}" --format \
                                "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}"
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 13. TRIVY IMAGE SECURITY SCAN (+ SBOM) — SECURITY GATE
        // ============================================================

        stage('TRIVY IMAGE SECURITY SCAN') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e

                            # SBOM CycloneDX (traçabilité)
                            trivy image \
                                --timeout "${TRIVY_TIMEOUT}" \
                                --format cyclonedx \
                                --output "${REPORTS_DIR}/sbom-cyclonedx.json" \
                                "${DOCKER_IMAGE}"

                            # Résultats détaillés (JSON) pour le rapport
                            trivy image \
                                --scanners vuln \
                                --severity HIGH,CRITICAL \
                                --ignore-unfixed \
                                --timeout "${TRIVY_TIMEOUT}" \
                                --exit-code 0 \
                                --format json \
                                --output "${REPORTS_DIR}/trivy-image.json" \
                                "${DOCKER_IMAGE}"

                            # Security gate : bloque sur HIGH/CRITICAL corrigeables
                            trivy image \
                                --scanners vuln \
                                --severity HIGH,CRITICAL \
                                --ignore-unfixed \
                                --timeout "${TRIVY_TIMEOUT}" \
                                --exit-code 1 \
                                --format table \
                                --output "${REPORTS_DIR}/trivy-image.txt" \
                                "${DOCKER_IMAGE}" \
                            || { cat "${REPORTS_DIR}/trivy-image.txt"; exit 1; }

                            cat "${REPORTS_DIR}/trivy-image.txt"
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 14. PUSH TO DOCKERHUB
        // ============================================================

        stage('PUSH TO DOCKERHUB') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        withCredentials([usernamePassword(
                            credentialsId: 'dockerhub-creds',
                            usernameVariable: 'DOCKER_USERNAME',
                            passwordVariable: 'DOCKER_PASSWORD'
                        )]) {
                            sh '''
                                set -e
                                echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin

                                # Réseau WSL2 instable : 3 tentatives (les couches déjà envoyées ne sont pas renvoyées)
                                for i in 1 2 3; do
                                    if docker push "${DOCKER_IMAGE}"; then
                                        echo "Push OK (tentative $i)"
                                        break
                                    fi
                                    if [ "$i" -eq 3 ]; then
                                        echo "Push KO apres 3 tentatives"
                                        docker logout || true
                                        exit 1
                                    fi
                                    echo "Push interrompu, nouvelle tentative dans 15 s..."
                                    sleep 15
                                done

                                docker logout
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 15. DEPLOY (Kubernetes / minikube)
        // ============================================================

        stage('DEPLOY') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        withCredentials([usernamePassword(
                            credentialsId: 'timesheet-db',
                            usernameVariable: 'DB_USERNAME',
                            passwordVariable: 'DB_PASSWORD'
                        )]) {
                            sh '''
                                set -e

                                kubectl get nodes

                                kubectl apply -f k8s/namespace.yaml

                                kubectl create secret generic mysql-secret \
                                    -n "${K8S_NAMESPACE}" \
                                    --from-literal=MYSQL_USER="${DB_USERNAME}" \
                                    --from-literal=MYSQL_PASSWORD="${DB_PASSWORD}" \
                                    --dry-run=client -o yaml | kubectl apply -f -

                                kubectl apply \
                                    -f k8s/mysql-pvc.yaml \
                                    -f k8s/mysql-deployment.yaml \
                                    -f k8s/mysql-service.yaml

                                kubectl apply \
                                    -f k8s/timesheet-deployment.yaml \
                                    -f k8s/timesheet-service.yaml

                                # Prometheus : la config est montée en subPath (jamais rechargée à chaud)
                                # => redémarrage uniquement si le ConfigMap (prometheus.yml / alerts.yml) a changé
                                CM_OUT=$(kubectl apply -f k8s/prometheus-configmap.yaml)
                                echo "${CM_OUT}"
                                kubectl apply \
                                    -f k8s/prometheus-deployment.yaml \
                                    -f k8s/prometheus-service.yaml
                                if echo "${CM_OUT}" | grep -q configured; then
                                    echo "Configuration Prometheus modifiée : redémarrage"
                                    kubectl rollout restart deployment/prometheus -n "${K8S_NAMESPACE}"
                                fi

                                if [ -f k8s/grafana-deployment.yaml ] && [ -f k8s/grafana-service.yaml ]; then
                                    kubectl apply -f k8s/grafana-deployment.yaml -f k8s/grafana-service.yaml
                                else
                                    echo "Grafana manifests not found. Skipping."
                                fi

                                kubectl set image deployment/timesheet \
                                    timesheet="${DOCKER_IMAGE}" \
                                    -n "${K8S_NAMESPACE}"

                                if ! kubectl rollout status deployment/timesheet \
                                        -n "${K8S_NAMESPACE}" --timeout=300s; then
                                    echo "=========== ROLLOUT KO : DIAGNOSTIC ==========="
                                    kubectl get pods -n "${K8S_NAMESPACE}" -o wide || true
                                    kubectl describe pods -n "${K8S_NAMESPACE}" -l app=timesheet | tail -n 40 || true
                                    kubectl logs deployment/timesheet -n "${K8S_NAMESPACE}" --tail=80 || true
                                    kubectl get events -n "${K8S_NAMESPACE}" --sort-by=.lastTimestamp | tail -n 20 || true
                                    echo "=========== ROLLBACK vers la version precedente ==========="
                                    kubectl rollout undo deployment/timesheet -n "${K8S_NAMESPACE}" || true
                                    exit 1
                                fi
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 16. HEALTH CHECK (via kubectl port-forward)
        // ============================================================

        stage('HEALTH CHECK') {
            steps {
                script {
                    runStage(env.STAGE_NAME) {
                        sh '''
                            set -e
                            PF_APP=""
                            PF_PROM=""
                            trap 'kill $PF_APP $PF_PROM 2>/dev/null || true' EXIT

                            kubectl get pods -n "${K8S_NAMESPACE}" -o wide

                            for d in mysqldb timesheet prometheus; do
                                kubectl rollout status "deployment/$d" -n "${K8S_NAMESPACE}" --timeout=180s
                            done

                            kubectl port-forward "svc/${APP_SERVICE}" "${LOCAL_APP_PORT}:${APP_PORT}" \
                                -n "${K8S_NAMESPACE}" > pf-app.log 2>&1 &
                            PF_APP=$!

                            kubectl port-forward "svc/${PROM_SERVICE}" "${LOCAL_PROM_PORT}:9090" \
                                -n "${K8S_NAMESPACE}" > pf-prom.log 2>&1 &
                            PF_PROM=$!

                            HEALTH_URL="http://localhost:${LOCAL_APP_PORT}${APP_CONTEXT_PATH}/actuator/health"

                            echo "Waiting for ${HEALTH_URL} ..."
                            for i in $(seq 1 30); do
                                if curl -fsS "${HEALTH_URL}" | grep -q '"status":"UP"'; then
                                    echo "Timesheet application is UP."
                                    break
                                fi
                                if [ "$i" -eq 30 ]; then
                                    echo "Application health check FAILED"
                                    cat pf-app.log
                                    exit 1
                                fi
                                sleep 5
                            done

                            curl -fsS "http://localhost:${LOCAL_PROM_PORT}/-/healthy"
                            echo ""
                            echo "Prometheus (k8s) is healthy."
                        '''
                    }
                }
            }
        }

        // ============================================================
        // 17. CONFIG SAFETY - KUBESCAPE   [PRODUCTION] (non bloquant)
        //     Conformité du cluster aux référentiels NSA-CISA et MITRE ATT&CK
        // ============================================================

        stage('CONFIG SAFETY - KUBESCAPE') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {
                            sh '''
                                set -e
                                echo "============ KUBESCAPE (NSA + MITRE) ============"
                                kubescape scan framework nsa,mitre \
                                    --include-namespaces "${K8S_NAMESPACE}" \
                                    --format json \
                                    --output "${REPORTS_DIR}/kubescape.json"

                                # Résumé lisible + seuil de conformité (exit 1 => UNSTABLE)
                                python3 ci/runtime_checks.py kubescape \
                                    "${REPORTS_DIR}/kubescape.json" "${KUBESCAPE_THRESHOLD}"
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 18. SERVER HARDENING - LYNIS   [PRODUCTION] (non bloquant)
        //     Audit de durcissement du serveur qui exécute le pipeline
        // ============================================================

        stage('SERVER HARDENING - LYNIS') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {
                            sh '''
                                set -e
                                echo "============ LYNIS AUDIT ============"
                                rc=0
                                lynis audit system --quick --no-colors \
                                    --report-file "${REPORTS_DIR}/lynis-report.dat" \
                                    --log-file "${REPORTS_DIR}/lynis.log" \
                                    > "${REPORTS_DIR}/lynis.txt" 2>&1 || rc=$?
                                echo "Lynis termine (code ${rc})"

                                # Hardening Index + avertissements (exit 1 => UNSTABLE)
                                python3 ci/runtime_checks.py lynis \
                                    "${REPORTS_DIR}/lynis-report.dat" "${LYNIS_MIN_SCORE}"
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 19. DAST - OWASP ZAP BASELINE   [TEST] (non bloquant)
        // ============================================================

        stage('DAST - OWASP ZAP') {
            environment {
                // Image officielle ZAP sur Docker Hub (GHCR coupe souvent les gros pulls sous WSL2)
                ZAP_IMAGE = 'zaproxy/zap-stable'
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {

                            // 1) Image : pull seulement si absente, 3 tentatives
                            retry(3) {
                                sh '''
                                    docker image inspect "${ZAP_IMAGE}" > /dev/null 2>&1 \
                                      || docker pull "${ZAP_IMAGE}"
                                '''
                            }

                            // 2) Port-forward + attente de l'application + scan baseline
                            sh '''
                                set -e
                                PF_APP=""
                                trap 'kill $PF_APP 2>/dev/null || true' EXIT

                                kubectl port-forward "svc/${APP_SERVICE}" "${LOCAL_APP_PORT}:${APP_PORT}" \
                                    -n "${K8S_NAMESPACE}" > "${REPORTS_DIR}/pf-zap.log" 2>&1 &
                                PF_APP=$!

                                TARGET="http://localhost:${LOCAL_APP_PORT}${APP_CONTEXT_PATH}"
                                for i in $(seq 1 30); do
                                    if curl -fsS "${TARGET}/actuator/health" | grep -q '"status":"UP"'; then
                                        echo "Application joignable pour ZAP"
                                        break
                                    fi
                                    [ "$i" -eq 30 ] && { echo "Application injoignable"; cat "${REPORTS_DIR}/pf-zap.log"; exit 1; }
                                    sleep 2
                                done

                                docker run --rm --network host \
                                    -v "$(pwd)/${REPORTS_DIR}:/zap/wrk:rw" \
                                    "${ZAP_IMAGE}" \
                                    zap-baseline.py \
                                        -t "${TARGET}/" \
                                        -r zap-report.html \
                                        -J zap-report.json \
                                        -I
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 20. SECURITY TESTS - GAUNTLT   [TEST] (tests d'attaque BDD, non bloquant)
        // ============================================================

        stage('SECURITY TESTS - GAUNTLT') {
            environment {
                GAUNTLT_IMAGE = 'gauntlt-local:1.0.13'
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {

                            // 1) Image Gauntlt : construite une seule fois (réutilisée ensuite)
                            retry(2) {
                                sh '''
                                    docker image inspect "${GAUNTLT_IMAGE}" > /dev/null 2>&1 \
                                      || docker build -t "${GAUNTLT_IMAGE}" security/gauntlt
                                '''
                            }

                            // 2) Port-forward vers l'application + exécution des attaques
                            sh '''
                                set -e
                                PF_APP=""
                                trap 'kill $PF_APP 2>/dev/null || true' EXIT

                                kubectl port-forward "svc/${APP_SERVICE}" "${LOCAL_APP_PORT}:${APP_PORT}" \
                                    -n "${K8S_NAMESPACE}" > "${REPORTS_DIR}/pf-gauntlt.log" 2>&1 &
                                PF_APP=$!

                                TARGET="http://localhost:${LOCAL_APP_PORT}${APP_CONTEXT_PATH}"
                                for i in $(seq 1 30); do
                                    if curl -fsS "${TARGET}/actuator/health" | grep -q '"status":"UP"'; then
                                        echo "Application joignable pour Gauntlt"
                                        break
                                    fi
                                    [ "$i" -eq 30 ] && { echo "Application injoignable"; exit 1; }
                                    sleep 2
                                done

                                # Les attaques sont montées en lecture seule et copiées dans le conteneur
                                # (aucun fichier root n'est créé dans le workspace Jenkins)
                                rc=0
                                docker run --rm --network host \
                                    -v "$(pwd)/security/gauntlt:/src:ro" \
                                    "${GAUNTLT_IMAGE}" \
                                    sh -c 'cp /src/*.attack /tmp/attacks/ && cd /tmp/attacks && gauntlt *.attack' \
                                    > "${REPORTS_DIR}/gauntlt.txt" 2>&1 || rc=$?

                                cat "${REPORTS_DIR}/gauntlt.txt"
                                exit $rc
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 21. HOST INTRUSION - FALCO   [PRODUCTION] (non bloquant)
        //     Simule un comportement d'attaquant dans le pod déployé
        //     et vérifie que Falco le détecte en temps réel
        // ============================================================

        stage('HOST INTRUSION - FALCO') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {
                            sh '''
                                set -e
                                echo "============ FALCO RUNTIME DETECTION ============"
                                kubectl rollout status daemonset/falco -n "${FALCO_NAMESPACE}" --timeout=120s

                                START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
                                POD=$(kubectl get pod -n "${K8S_NAMESPACE}" -l app=timesheet \
                                        --field-selector=status.phase=Running \
                                        -o jsonpath='{.items[0].metadata.name}')
                                echo "Attaque simulee dans le pod : ${POD}"

                                # 1) Lecture d'un fichier d'authentification sensible
                                kubectl exec -n "${K8S_NAMESPACE}" "${POD}" -- cat /etc/pam.conf > /dev/null 2>&1 || true
                                # 2) Recherche de cles privees / lecture de /etc/shadow (refusee : conteneur non-root)
                                kubectl exec -n "${K8S_NAMESPACE}" "${POD}" -- \
                                    sh -c 'find / -maxdepth 3 -name id_rsa 2>/dev/null; cat /etc/shadow 2>/dev/null; true' || true

                                sleep 15
                                kubectl logs -n "${FALCO_NAMESPACE}" -l app.kubernetes.io/name=falco -c falco \
                                    --since-time="${START}" --tail=-1 > "${REPORTS_DIR}/falco.txt" 2>&1 || true

                                # Alertes detectees (exit 1 => aucune detection => UNSTABLE)
                                python3 ci/runtime_checks.py falco "${REPORTS_DIR}/falco.txt" "${POD}"
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 22. CONTINUOUS SCANNING - TRIVY OPERATOR   [OPERATIONS] (non bloquant)
        //     Rapports de vulnérabilités des workloads en cours d'exécution
        // ============================================================

        stage('CONTINUOUS SCANNING - TRIVY OPERATOR') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {
                            sh '''
                                set -e
                                echo "============ TRIVY OPERATOR ============"
                                kubectl rollout status deployment/trivy-operator -n "${TRIVY_OP_NAMESPACE}" --timeout=120s

                                # Attente du rapport de la nouvelle image (tag = numero de build), 5 min max
                                FOUND=0
                                for i in $(seq 1 30); do
                                    if kubectl get vulnerabilityreports -n "${K8S_NAMESPACE}" \
                                            -o jsonpath='{range .items[*]}{.report.artifact.tag}{"\\n"}{end}' \
                                            | grep -qx "${BUILD_NUMBER}"; then
                                        FOUND=1
                                        echo "Rapport de l'image ${DOCKER_IMAGE} disponible"
                                        break
                                    fi
                                    echo "Scan de ${DOCKER_IMAGE} en cours... (${i}/30)"
                                    sleep 10
                                done

                                kubectl get vulnerabilityreports -n "${K8S_NAMESPACE}" -o json \
                                    > "${REPORTS_DIR}/trivy-operator-vulns.json"
                                kubectl get configauditreports -n "${K8S_NAMESPACE}" -o json \
                                    > "${REPORTS_DIR}/trivy-operator-config.json" || echo '{"items":[]}' > "${REPORTS_DIR}/trivy-operator-config.json"
                                kubectl get exposedsecretreports -n "${K8S_NAMESPACE}" -o json \
                                    > "${REPORTS_DIR}/trivy-operator-secrets.json" || echo '{"items":[]}' > "${REPORTS_DIR}/trivy-operator-secrets.json"
                                kubectl get vulnerabilityreports -n "${K8S_NAMESPACE}" -o wide \
                                    > "${REPORTS_DIR}/trivy-operator.txt" || true

                                # Synthese (exit 1 si CVE CRITICAL dans l'image deployee => UNSTABLE)
                                python3 ci/runtime_checks.py trivy-operator "${REPORTS_DIR}" "${BUILD_NUMBER}" "${FOUND}"
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 23. CONTINUOUS MONITORING - PROMETHEUS & GRAFANA   [OPERATIONS] (non bloquant)
        //     Vérifie la supervision : cibles UP, règles d'alerte, alertes actives, Grafana
        // ============================================================

        stage('CONTINUOUS MONITORING - PROMETHEUS') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        runStage(env.STAGE_NAME) {
                            sh '''
                                set -e
                                echo "============ PROMETHEUS & GRAFANA ============"
                                PF_PROM=""
                                trap 'kill $PF_PROM 2>/dev/null || true' EXIT

                                kubectl rollout status deployment/prometheus -n "${K8S_NAMESPACE}" --timeout=180s
                                kubectl rollout status "deployment/${GRAFANA_SERVICE}" -n "${K8S_NAMESPACE}" --timeout=180s

                                kubectl port-forward "svc/${PROM_SERVICE}" "${LOCAL_PROM_PORT}:9090" \
                                    -n "${K8S_NAMESPACE}" > "${REPORTS_DIR}/pf-prom.log" 2>&1 &
                                PF_PROM=$!
                                PROM="http://localhost:${LOCAL_PROM_PORT}"

                                for i in $(seq 1 30); do
                                    curl -fsS "${PROM}/-/ready" > /dev/null 2>&1 && break
                                    [ "$i" -eq 30 ] && { echo "Prometheus injoignable"; cat "${REPORTS_DIR}/pf-prom.log"; exit 1; }
                                    sleep 2
                                done

                                # Prometheus peut avoir redemarre au DEPLOY : on attend un cycle de collecte complet (2 min max)
                                for i in $(seq 1 12); do
                                    curl -fsS "${PROM}/api/v1/targets?state=active" -o "${REPORTS_DIR}/prometheus-targets.json"
                                    python3 ci/runtime_checks.py targets-up "${REPORTS_DIR}/prometheus-targets.json" && break
                                    sleep 10
                                done

                                curl -fsS "${PROM}/api/v1/alerts" -o "${REPORTS_DIR}/prometheus-alerts.json"
                                curl -fsS "${PROM}/api/v1/rules"  -o "${REPORTS_DIR}/prometheus-rules.json"

                                kubectl exec -n "${K8S_NAMESPACE}" "deployment/${GRAFANA_SERVICE}" -- \
                                    wget -qO- http://localhost:3000/api/health > "${REPORTS_DIR}/grafana-health.json" 2>/dev/null \
                                    || echo '{}' > "${REPORTS_DIR}/grafana-health.json"

                                # Synthese (exit 1 si cible DOWN ou Grafana KO => UNSTABLE)
                                python3 ci/runtime_checks.py prometheus "${REPORTS_DIR}"
                            '''
                        }
                    }
                }
            }
        }

        // ============================================================
        // 24. EMAIL NOTIFICATION (uniquement si le build est SUCCESS)
        // ============================================================

        stage('EMAIL NOTIFICATION') {
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                script {
                    runStage(env.STAGE_NAME) {

                        // 1) Rapport à jour pour le corps du mail
                        writeReportInputs()
                        sh 'python3 ci/devsecops_report.py > /dev/null'
                        def resume = readFile("${env.REPORTS_DIR}/summary-line.txt").trim()

                        // 2) Envoi : corps = rapport HTML complet, + pièces jointes
                        emailext(
                            to: env.NOTIFY_EMAIL,
                            subject: "✅ SUCCESS - ${env.JOB_NAME} #${env.BUILD_NUMBER} - ${resume}",
                            mimeType: 'text/html',
                            body: '''<p>Bonjour,</p>
<p>Le pipeline <b>${JOB_NAME} #${BUILD_NUMBER}</b> s'est terminé avec succès.
L'image <b>${ENV,var="DOCKER_IMAGE"}</b> est déployée dans le namespace <b>${ENV,var="K8S_NAMESPACE"}</b>.</p>
<p>🔗 Build : <a href="${BUILD_URL}">${BUILD_URL}</a><br>
📊 Rapport en ligne : <a href="${BUILD_URL}DevSecOps_20Report/">${BUILD_URL}DevSecOps_20Report/</a></p>
<hr>
${FILE,path="reports/devsecops-report-email.html"}''',
                            attachmentsPattern: 'reports/devsecops-report-email.html, reports/zap-report.html'
                        )
                        echo "E-mail de notification envoyé à ${env.NOTIFY_EMAIL}"
                    }
                }
            }
        }
    }

    // ================================================================
    // POST ACTIONS  (triple guillemets doubles => variables interpolées)
    // ================================================================

    post {

        always {
            // 1) Statut + durée de chaque stage -> reports/stages.txt
            script {
                writeReportInputs()
            }

            // 2) Génération du rapport DevSecOps (HTML + résumé console)
            sh '''
                if [ -f ci/devsecops_report.py ]; then
                    python3 ci/devsecops_report.py \
                        || echo "Generation du rapport DevSecOps impossible (non bloquant)"
                else
                    echo "ci/devsecops_report.py introuvable : rapport non genere"
                fi
            '''

            // 3) Résumé court dans la description du build + publication HTML
            script {
                if (fileExists("${env.REPORTS_DIR}/summary-line.txt")) {
                    currentBuild.description = readFile("${env.REPORTS_DIR}/summary-line.txt").trim()
                }
                try {
                    publishHTML(target: [
                        reportDir            : env.REPORTS_DIR,
                        reportFiles          : 'devsecops-report.html, zap-report.html',
                        reportTitles         : 'DevSecOps, OWASP ZAP',
                        reportName           : 'DevSecOps Report',
                        keepAll              : true,
                        alwaysLinkToLastBuild: true,
                        allowMissing         : true
                    ])
                } catch (Throwable t) {
                    echo "Plugin HTML Publisher absent : rapport disponible dans les artefacts (reports/devsecops-report.html)"
                }
            }

            archiveArtifacts(artifacts: 'reports/**', allowEmptyArchive: true)
            sh 'docker logout || true'
            echo """
======================================
          PIPELINE SUMMARY
======================================
Job       : ${env.JOB_NAME}
Build     : #${env.BUILD_NUMBER}
Result    : ${currentBuild.currentResult}
Image     : ${env.DOCKER_IMAGE}
Namespace : ${env.K8S_NAMESPACE}
Build URL : ${env.BUILD_URL}
Rapport   : ${env.BUILD_URL}DevSecOps_20Report/
======================================
"""
        }

        success {
            echo "PIPELINE SUCCESS - ${env.DOCKER_IMAGE} déployée dans ${env.K8S_NAMESPACE}"
        }

        unstable {
            echo "PIPELINE UNSTABLE - un contrôle non bloquant a signalé un risque (voir le rapport DevSecOps)"
        }

        failure {
            echo "PIPELINE FAILURE - consulter la console et le rapport DevSecOps"
        }
    }
}
