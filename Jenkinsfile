pipeline {

    agent any

    environment {
        // =========================
        // Docker
        // =========================
        DOCKER_REPOSITORY = 'nouuur/timesheet'
        IMAGE_TAG = "${BUILD_NUMBER}"
        DOCKER_IMAGE = "${DOCKER_REPOSITORY}:${IMAGE_TAG}"

        // =========================
        // Kubernetes
        // =========================
        K8S_NAMESPACE = 'timesheet-platform'

        // =========================
        // Application
        // =========================
        APP_PORT = '8082'
        APP_CONTEXT_PATH = '/timesheet-devops'
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
                    echo "        TOOL CHECK"
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
                    echo "=== Trivy ==="
                    trivy --version

                    echo ""
                    echo "=== Git ==="
                    git --version

                    echo ""
                    echo "=== Pre-commit ==="
                    pre-commit --version || true

                    echo ""
                    echo "All required tools checked."
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

                    branches: [[
                        name: '*/master'
                    ]],

                    userRemoteConfigs: [[
                        url: 'https://github.com/nour-messaoudi/timesheet-project.git',
                        credentialsId: 'github-token'
                    ]],

                    extensions: [
                        [$class: 'CleanBeforeCheckout']
                    ]
                ])

                sh '''
                    echo "======================================"
                    echo "        GITHUB CHECKOUT"
                    echo "======================================"

                    git branch --show-current
                    git log -1 --oneline
                '''
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
                    echo "        CLEAN PROJECT"
                    echo "======================================"

                    mvn clean
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
                    echo "        BUILD ARTIFACT"
                    echo "======================================"

                    mvn package -DskipTests

                    echo ""
                    echo "Generated artifacts:"
                    ls -lh target/*.jar
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
                    echo "        UNIT & SECURITY TESTS"
                    echo "======================================"

                    mvn test
                '''
            }

            post {
                always {
                    junit(
                        allowEmptyResults: true,
                        testResults: 'target/surefire-reports/*.xml'
                    )
                }
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
                            echo "        SONARQUBE ANALYSIS"
                            echo "======================================"

                            mvn sonar:sonar \
                                -Dsonar.token="$SONAR_TOKEN"
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
                '''
            }
        }


        // ============================================================
        // 8. DEPENDENCY SECURITY SCAN
        // ============================================================
        stage('DEPENDENCY SECURITY SCAN') {
            steps {
                sh '''
                    set -e

                    echo "======================================"
                    echo "        DEPENDENCY SECURITY SCAN"
                    echo "======================================"

                    mvn org.owasp:dependency-check-maven:check
                '''
            }
        }


        // ============================================================
        // 9. PUBLISH / ARCHIVE ARTIFACT
        // ============================================================
        stage('PUBLISH/ARCHIVE ARTIFACT') {
            steps {

                echo "Archiving Maven artifact..."

                archiveArtifacts(
                    artifacts: 'target/*.jar',
                    fingerprint: true
                )
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
                    echo "        BUILD DOCKER IMAGE"
                    echo "======================================"

                    echo "Image: ${DOCKER_IMAGE}"

                    docker build \
                        -t "${DOCKER_IMAGE}" .

                    echo ""
                    echo "Docker image created:"
                    docker images "${DOCKER_REPOSITORY}"
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
                    echo "        TRIVY SECURITY SCAN"
                    echo "======================================"

                    echo "Scanning image:"
                    echo "${DOCKER_IMAGE}"

                    trivy image \
                        --severity HIGH,CRITICAL \
                        --exit-code 1 \
                        "${DOCKER_IMAGE}"
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
                        echo "        PUSH TO DOCKERHUB"
                        echo "======================================"

                        echo "$DOCKER_PASSWORD" | \
                            docker login \
                            --username "$DOCKER_USERNAME" \
                            --password-stdin

                        docker push "${DOCKER_IMAGE}"

                        docker logout
                    '''
                }
            }
        }


        // ============================================================
        // 13. DEPLOY
        // ============================================================
        stage('DEPLOY') {
            steps {
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
                    echo "=== MySQL ==="

                    kubectl apply \
                        -f k8s/mysql-secret.yaml

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
                '''
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
                    echo "        HEALTH CHECK"
                    echo "======================================"

                    echo ""
                    echo "=== MySQL rollout ==="

                    kubectl rollout status \
                        deployment/mysqldb \
                        -n "${K8S_NAMESPACE}" \
                        --timeout=180s

                    echo ""
                    echo "=== Timesheet rollout ==="

                    kubectl rollout status \
                        deployment/timesheet \
                        -n "${K8S_NAMESPACE}" \
                        --timeout=180s

                    echo ""
                    echo "=== Prometheus rollout ==="

                    kubectl rollout status \
                        deployment/prometheus \
                        -n "${K8S_NAMESPACE}" \
                        --timeout=180s

                    echo ""
                    echo "=== Kubernetes Pods ==="

                    kubectl get pods \
                        -n "${K8S_NAMESPACE}"

                    echo ""
                    echo "=== Spring Boot Health ==="

                    HEALTH=$(kubectl exec \
                        deployment/timesheet \
                        -n "${K8S_NAMESPACE}" \
                        -- \
                        wget -qO- \
                        "http://localhost:${APP_PORT}${APP_CONTEXT_PATH}/actuator/health")

                    echo "$HEALTH"

                    echo "$HEALTH" | grep -q '"status":"UP"'

                    echo ""
                    echo "Spring Boot health check passed."

                    echo ""
                    echo "=== Prometheus Endpoint ==="

                    kubectl exec \
                        deployment/timesheet \
                        -n "${K8S_NAMESPACE}" \
                        -- \
                        wget -qO- \
                        "http://localhost:${APP_PORT}${APP_CONTEXT_PATH}/actuator/prometheus" \
                        | head -n 10

                    echo ""
                    echo "Prometheus metrics endpoint is available."

                    echo ""
                    echo "======================================"
                    echo "       DEPLOYMENT SUCCESSFUL"
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

            echo """
========================================
 PIPELINE SUCCESS
========================================

Job:        ${JOB_NAME}
Build:      #${BUILD_NUMBER}
Result:     SUCCESS

Docker image:
${DOCKER_IMAGE}

Kubernetes namespace:
${K8S_NAMESPACE}

========================================
"""
        }

        failure {

            echo """
========================================
 PIPELINE FAILED
========================================

Job:        ${JOB_NAME}
Build:      #${BUILD_NUMBER}
Result:     FAILURE

Check the Jenkins console output.

========================================
"""
        }

        always {

            echo """
========================================
 PIPELINE SUMMARY
========================================

Job:        ${JOB_NAME}
Build:      #${BUILD_NUMBER}
Result:     ${currentBuild.currentResult}
Image:      ${DOCKER_IMAGE}
Namespace:  ${K8S_NAMESPACE}

========================================
"""
        }
    }
}
