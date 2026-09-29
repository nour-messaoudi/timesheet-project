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
        LOCAL_PROM_PORT   = '19090'

        // SonarQube
        SONAR_PROJECT_KEY = 'tn.esprit.spring.services:timesheet-devops'

        // DevSecOps
        REPORTS_DIR       = 'reports'
        TRIVY_TIMEOUT     = '20m'
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

                                kubectl apply \
                                    -f k8s/prometheus-configmap.yaml \
                                    -f k8s/prometheus-deployment.yaml \
                                    -f k8s/prometheus-service.yaml

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
        // 17. DAST - OWASP ZAP BASELINE (non bloquant)
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
    }

    // ================================================================
    // POST ACTIONS  (triple guillemets doubles => variables interpolées)
    // ================================================================

    post {

        always {
            // 1) Statut + durée de chaque stage -> reports/stages.txt
            script {
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
            echo "PIPELINE UNSTABLE - voir le rapport ZAP dans les artefacts (reports/zap-report.html)"
        }

        failure {
            echo "PIPELINE FAILURE - consulter la console et le rapport DevSecOps"
        }
    }
}
