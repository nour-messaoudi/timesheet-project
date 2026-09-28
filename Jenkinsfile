pipeline {

    agent any

    environment {

        // ============================================================
        // APPLICATION
        // ============================================================

        APP_NAME = 'timesheet'
        APP_PORT = '8082'
        APP_CONTEXT_PATH = '/timesheet-devops'


        // ============================================================
        // DOCKER
        // ============================================================

        DOCKER_REPOSITORY = 'nouuur/timesheet'
        IMAGE_TAG = "${BUILD_NUMBER}"
        DOCKER_IMAGE = "${DOCKER_REPOSITORY}:${BUILD_NUMBER}"


        // ============================================================
        // KUBERNETES
        // ============================================================

        K8S_NAMESPACE = 'timesheet-platform'


        // ============================================================
        // MAVEN
        // ============================================================

        MAVEN_OPTS = '-Dmaven.repo.local=/var/lib/jenkins/.m2/repository'
    }


    stages {

        // ============================================================
        // 1. TOOL CHECK
        // ============================================================

        stage('TOOL CHECK') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "             TOOL CHECK"
                    echo "======================================"

                    echo ""
                    echo "=== Java ==="
                    java -version

                    echo ""
                    echo "=== Maven ==="
                    mvn -version

                    echo ""
                    echo "=== Docker ==="
                    docker --version

                    echo ""
                    echo "=== kubectl ==="
                    kubectl version --client

                    echo ""
                    echo "=== Minikube ==="
                    minikube version

                    echo ""
                    echo "=== Trivy ==="
                    trivy --version

                    echo ""
                    echo "=== Git ==="
                    git --version

                    echo ""
                    echo "=== Pre-commit ==="
                    pre-commit --version

                    echo ""
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
                    extensions: [
                        [$class: 'CleanBeforeCheckout']
                    ]
                ])
            }
        }


        // ============================================================
        // 3. CLEAN PROJECT
        // ============================================================

        stage('CLEAN PROJECT') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "           CLEAN PROJECT"
                    echo "======================================"

                    mvn clean

                    echo ""
                    echo "Project cleaned successfully."
                '''
            }
        }


        // ============================================================
        // 4. BUILD ARTIFACT
        // ============================================================

        stage('BUILD ARTIFACT') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "           BUILD ARTIFACT"
                    echo "======================================"

                    mvn package -DskipTests

                    echo ""
                    echo "Generated artifacts:"
                    ls -lh target/*.jar

                    echo ""
                    echo "Artifact build completed successfully."
                '''
            }
        }


        // ============================================================
        // 5. UNIT & SECURITY TESTS
        // ============================================================

        stage('UNIT & SECURITY TESTS') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "       UNIT & SECURITY TESTS"
                    echo "======================================"

                    mvn test
                '''

                junit(
                    testResults: 'target/surefire-reports/*.xml',
                    allowEmptyResults: false
                )
            }
        }


        // ============================================================
        // 6. SONARQUBE / CODE QUALITY
        // ============================================================

        stage('SONARQUBE / CODE QUALITY') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    withCredentials([
                        string(
                            credentialsId: 'sonar-token',
                            variable: 'SONAR_TOKEN'
                        )
                    ]) {
                        sh '''
                            set -e

                            echo "======================================"
                            echo "       SONARQUBE / CODE QUALITY"
                            echo "======================================"

                            mvn sonar:sonar \
                                -Dsonar.token="${SONAR_TOKEN}"
                        '''
                    }
                }
            }
        }


        // ============================================================
        // 7. SECRET SECURITY SCAN
        // ============================================================

        stage('SECRET SECURITY SCAN') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "        SECRET SECURITY SCAN"
                    echo "======================================"

                    pre-commit run --all-files

                    echo ""
                    echo "Secret security scan completed successfully."
                '''
            }
        }


        // ============================================================
        // 8. DEPENDENCY SECURITY SCAN
        // ============================================================

        stage('DEPENDENCY SECURITY SCAN') {
            steps {
                withCredentials([
                    string(
                        credentialsId: 'nvd-api-key',
                        variable: 'NVD_API_KEY'
                    )
                ]) {
                    sh '''
                        set -e

                        echo "======================================"
                        echo "       DEPENDENCY SECURITY SCAN"
                        echo "======================================"

                        mvn org.owasp:dependency-check-maven:check \
                            -DnvdApiKeyEnvironmentVariable=NVD_API_KEY

                        echo ""
                        echo "Dependency security scan completed successfully."
                    '''
                }
            }
        }


        // ============================================================
        // 9. PUBLISH / ARCHIVE ARTIFACT
        // ============================================================

        stage('PUBLISH/ARCHIVE ARTIFACT') {
            steps {
                archiveArtifacts(
                    artifacts: 'target/*.jar',
                    fingerprint: true
                )

                echo "Artifact archived successfully."
            }
        }


        // ============================================================
        // 10. BUILD DOCKER IMAGE
        // ============================================================

        stage('BUILD DOCKER IMAGE') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "         BUILD DOCKER IMAGE"
                    echo "======================================"

                    echo "Docker image:"
                    echo "${DOCKER_IMAGE}"

                    docker build \
                        -t "${DOCKER_IMAGE}" \
                        .

                    echo ""
                    echo "Docker image built successfully."

                    docker images "${DOCKER_REPOSITORY}" --format \
                        "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}"
                '''
            }
        }


        // ============================================================
        // 11. TRIVY IMAGE SECURITY SCAN
        // ============================================================

        stage('TRIVY IMAGE SECURITY SCAN') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "       TRIVY IMAGE SECURITY SCAN"
                    echo "======================================"

                    echo "Scanning image:"
                    echo "${DOCKER_IMAGE}"

                    trivy image \
                        --severity HIGH,CRITICAL \
                        --exit-code 1 \
                        "${DOCKER_IMAGE}"

                    echo ""
                    echo "Trivy security scan completed successfully."
                '''
            }
        }


        // ============================================================
        // 12. PUSH TO DOCKERHUB
        // ============================================================

        stage('PUSH TO DOCKERHUB') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'dockerhub-creds',
                        usernameVariable: 'DOCKER_USERNAME',
                        passwordVariable: 'DOCKER_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -e

                        echo "======================================"
                        echo "          PUSH TO DOCKERHUB"
                        echo "======================================"

                        echo "${DOCKER_PASSWORD}" | docker login \
                            -u "${DOCKER_USERNAME}" \
                            --password-stdin

                        docker push "${DOCKER_IMAGE}"

                        docker logout

                        echo ""
                        echo "Docker image pushed successfully."
                        echo "Image: ${DOCKER_IMAGE}"
                    '''
                }
            }
        }


        // ============================================================
        // 13. DEPLOY
        // ============================================================

        stage('DEPLOY') {
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'timesheet-db',
                        usernameVariable: 'DB_USERNAME',
                        passwordVariable: 'DB_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -e

                        echo "======================================"
                        echo "        KUBERNETES DEPLOYMENT"
                        echo "======================================"

                        echo ""
                        echo "=== Namespace ==="

                        kubectl apply \
                            -f k8s/namespace.yaml


                        echo ""
                        echo "=== MySQL Secret ==="

                        kubectl create secret generic mysql-secret \
                            -n "${K8S_NAMESPACE}" \
                            --from-literal=MYSQL_USER="${DB_USERNAME}" \
                            --from-literal=MYSQL_PASSWORD="${DB_PASSWORD}" \
                            --dry-run=client \
                            -o yaml | kubectl apply -f -


                        echo ""
                        echo "=== MySQL ==="

                        kubectl apply \
                            -f k8s/mysql-pvc.yaml

                        kubectl apply \
                            -f k8s/mysql-deployment.yaml

                        kubectl apply \
                            -f k8s/mysql-service.yaml


                        echo ""
                        echo "=== Timesheet Service ==="

                        kubectl apply \
                            -f k8s/timesheet-service.yaml


                        echo ""
                        echo "=== Prometheus ==="

                        kubectl apply \
                            -f k8s/prometheus-configmap.yaml

                        kubectl apply \
                            -f k8s/prometheus-deployment.yaml

                        kubectl apply \
                            -f k8s/prometheus-service.yaml


                        echo ""
                        echo "=== Grafana ==="

                        if [ -f k8s/grafana-deployment.yaml ]; then
                            kubectl apply \
                                -f k8s/grafana-deployment.yaml
                        fi

                        if [ -f k8s/grafana-service.yaml ]; then
                            kubectl apply \
                                -f k8s/grafana-service.yaml
                        fi


                        echo ""
                        echo "=== Deploy Timesheet Image ==="

                        echo "Image:"
                        echo "${DOCKER_IMAGE}"

                        kubectl set image \
                            deployment/timesheet \
                            timesheet="${DOCKER_IMAGE}" \
                            -n "${K8S_NAMESPACE}"


                        echo ""
                        echo "=== Deployment image ==="

                        kubectl get deployment timesheet \
                            -n "${K8S_NAMESPACE}" \
                            -o jsonpath='{.spec.template.spec.containers[0].image}'

                        echo ""

                        echo ""
                        echo "Kubernetes deployment completed successfully."
                    '''
                }
            }
        }


        // ============================================================
        // 14. HEALTH CHECK
        // ============================================================

        stage('HEALTH CHECK') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "             HEALTH CHECK"
                    echo "======================================"


                    echo ""
                    echo "=== MySQL Rollout ==="

                    kubectl rollout status \
                        deployment/mysqldb \
                        -n "${K8S_NAMESPACE}" \
                        --timeout=180s


                    echo ""
                    echo "=== Timesheet Rollout ==="

                    kubectl rollout status \
                        deployment/timesheet \
                        -n "${K8S_NAMESPACE}" \
                        --timeout=180s


                    echo ""
                    echo "=== Prometheus Rollout ==="

                    kubectl rollout status \
                        deployment/prometheus \
                        -n "${K8S_NAMESPACE}" \
                        --timeout=180s


                    echo ""
                    echo "=== Kubernetes Pods ==="

                    kubectl get pods \
                        -n "${K8S_NAMESPACE}" \
                        -o wide


                    echo ""
                    echo "=== Kubernetes Services ==="

                    kubectl get services \
                        -n "${K8S_NAMESPACE}"


                    echo ""
                    echo "=== Minikube IP ==="

                    MINIKUBE_IP=$(minikube ip)

                    echo "${MINIKUBE_IP}"


                    echo ""
                    echo "=== Timesheet Service Health ==="

                    TIMESHEET_NODE_PORT=$(kubectl get service timesheet \
                        -n "${K8S_NAMESPACE}" \
                        -o jsonpath='{.spec.ports[0].nodePort}')

                    TIMESHEET_URL="http://${MINIKUBE_IP}:${TIMESHEET_NODE_PORT}${APP_CONTEXT_PATH}/actuator/health"

                    echo "Timesheet URL:"
                    echo "${TIMESHEET_URL}"

                    HEALTH_RESPONSE=$(wget -qO- "${TIMESHEET_URL}" || true)

                    echo "Response:"
                    echo "${HEALTH_RESPONSE}"

                    if echo "${HEALTH_RESPONSE}" | grep -q '"status":"UP"'; then
                        echo ""
                        echo "Timesheet health check: PASS"
                    else
                        echo ""
                        echo "Timesheet health check: FAIL"
                        exit 1
                    fi


                    echo ""
                    echo "=== Prometheus Health ==="

                    PROMETHEUS_NODE_PORT=$(kubectl get service prometheus \
                        -n "${K8S_NAMESPACE}" \
                        -o jsonpath='{.spec.ports[0].nodePort}')

                    PROMETHEUS_URL="http://${MINIKUBE_IP}:${PROMETHEUS_NODE_PORT}/-/healthy"

                    echo "Prometheus URL:"
                    echo "${PROMETHEUS_URL}"

                    PROMETHEUS_RESPONSE=$(wget -qO- "${PROMETHEUS_URL}" || true)

                    echo "Response:"
                    echo "${PROMETHEUS_RESPONSE}"

                    if echo "${PROMETHEUS_RESPONSE}" | grep -qi "Prometheus Server is Healthy"; then
                        echo ""
                        echo "Prometheus health check: PASS"
                    else
                        echo ""
                        echo "Prometheus health check: FAIL"
                        exit 1
                    fi


                    echo ""
                    echo "=== Prometheus Metrics Endpoint ==="

                    METRICS_URL="http://${MINIKUBE_IP}:${TIMESHEET_NODE_PORT}${APP_CONTEXT_PATH}/actuator/prometheus"

                    echo "Metrics URL:"
                    echo "${METRICS_URL}"

                    METRICS_RESPONSE=$(wget -qO- "${METRICS_URL}" || true)

                    if echo "${METRICS_RESPONSE}" | grep -q "jvm_"; then
                        echo "Prometheus metrics endpoint: PASS"
                    else
                        echo "Prometheus metrics endpoint: FAIL"
                        exit 1
                    fi


                    echo ""
                    echo "======================================"
                    echo "       ALL HEALTH CHECKS PASSED"
                    echo "======================================"
                '''
            }
        }
    }


    // ================================================================
    // POST ACTIONS
    // ================================================================

    post {

        success {
            echo ""
            echo "======================================"
            echo "       PIPELINE SUCCESS"
            echo "======================================"

            echo "Build number : ${BUILD_NUMBER}"
            echo "Docker image : ${DOCKER_IMAGE}"
            echo "Namespace    : ${K8S_NAMESPACE}"

            echo ""
            echo "All pipeline stages completed successfully."
        }


        failure {
            echo ""
            echo "======================================"
            echo "       PIPELINE FAILURE"
            echo "======================================"

            echo "Build number : ${BUILD_NUMBER}"
            echo "Check the Jenkins console output for details."
        }


        always {
            echo ""
            echo "Pipeline finished with status: ${currentBuild.currentResult}"
        }
    }
}
