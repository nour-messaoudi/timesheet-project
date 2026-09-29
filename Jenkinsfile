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
                    curl --version | head -1
                    echo "All required tools are available."
                '''
            }
        }

        // ============================================================
        // 2. CHECKOUT FROM GITHUB
        // ============================================================

        stage('CHECKOUT FROM GITHUB') {
            steps {
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

        // ============================================================
        // 3. SECRET SECURITY SCAN  (shift-left : avant le build)
        // ============================================================

        stage('SECRET SECURITY SCAN') {
            steps {
                sh '''
                    set -e
                    echo "============ SECRET SECURITY SCAN ============"
                    pre-commit run --all-files
                '''
            }
        }

        // ============================================================
        // 4. CLEAN PROJECT
        // ============================================================

        stage('CLEAN PROJECT') {
            steps {
                sh 'mvn -B clean'
            }
        }

        // ============================================================
        // 5. BUILD ARTIFACT
        // ============================================================

        stage('BUILD ARTIFACT') {
            steps {
                sh '''
                    set -e
                    mvn -B package -DskipTests
                    ls -lh target/*.jar
                '''
            }
        }

        // ============================================================
        // 6. UNIT & SECURITY TESTS  (+ rapport de couverture JaCoCo)
        // ============================================================

        stage('UNIT & SECURITY TESTS') {
            steps {
                sh 'mvn -B test jacoco:report'
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
                withSonarQubeEnv('SonarQube') {
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

        // ============================================================
        // 8. QUALITY GATE  (nécessite le webhook SonarQube -> Jenkins)
        // ============================================================

        stage('QUALITY GATE') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        // ============================================================
        // 9. SCA - DEPENDENCIES SCAN (Trivy fs sur pom.xml)
        // ============================================================

        stage('SCA - DEPENDENCIES SCAN') {
            steps {
                sh '''
                    set -e
                    trivy fs \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --timeout "${TRIVY_TIMEOUT}" \
                        --exit-code 0 \
                        --format table \
                        --output "${REPORTS_DIR}/trivy-sca.txt" \
                        .
                    cat "${REPORTS_DIR}/trivy-sca.txt"
                '''
            }
        }

        // ============================================================
        // 10. IaC SCAN (Dockerfile + manifests k8s)
        // ============================================================

        stage('IaC SECURITY SCAN') {
            steps {
                sh '''
                    set -e
                    trivy config \
                        --severity HIGH,CRITICAL \
                        --exit-code 0 \
                        --format table \
                        --output "${REPORTS_DIR}/trivy-iac.txt" \
                        .
                    cat "${REPORTS_DIR}/trivy-iac.txt"
                '''
            }
        }

        // ============================================================
        // 11. PUBLISH / ARCHIVE ARTIFACT
        // ============================================================

        stage('PUBLISH/ARCHIVE ARTIFACT') {
            steps {
                archiveArtifacts(artifacts: 'target/*.jar', fingerprint: true)
            }
        }

        // ============================================================
        // 12. BUILD DOCKER IMAGE
        // ============================================================

        stage('BUILD DOCKER IMAGE') {
            steps {
                sh '''
                    set -e
                    docker build -t "${DOCKER_IMAGE}" .
                    docker images "${DOCKER_REPOSITORY}" --format \
                        "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}"
                '''
            }
        }

        // ============================================================
        // 13. TRIVY IMAGE SECURITY SCAN (+ SBOM)
        // ============================================================

        stage('TRIVY IMAGE SECURITY SCAN') {
            steps {
                sh '''
                    set -e

                    # SBOM CycloneDX (traçabilité)
                    trivy image \
                        --timeout "${TRIVY_TIMEOUT}" \
                        --format cyclonedx \
                        --output "${REPORTS_DIR}/sbom-cyclonedx.json" \
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

        // ============================================================
        // 14. PUSH TO DOCKERHUB
        // ============================================================

        stage('PUSH TO DOCKERHUB') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-creds',
                    usernameVariable: 'DOCKER_USERNAME',
                    passwordVariable: 'DOCKER_PASSWORD'
                )]) {
                    sh '''
                        set -e
                        echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin
                        docker push "${DOCKER_IMAGE}"
                        docker logout
                    '''
                }
            }
        }

        // ============================================================
        // 15. DEPLOY (Kubernetes / minikube)
        // ============================================================

        stage('DEPLOY') {
            steps {
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

                        kubectl rollout status deployment/timesheet \
                            -n "${K8S_NAMESPACE}" --timeout=300s
                    '''
                }
            }
        }

        // ============================================================
        // 16. HEALTH CHECK (via kubectl port-forward)
        // ============================================================

        stage('HEALTH CHECK') {
            steps {
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

    // ================================================================
    // POST ACTIONS  (triple guillemets doubles => variables interpolées)
    // ================================================================

    post {

        always {
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
            echo "PIPELINE FAILURE - consulter la console et les rapports dans reports/"
        }
    }
}
