pipeline {

    agent any

    // ============================================================
    // ENVIRONMENT
    // ============================================================

    environment {

        // Docker
        DOCKER_REPOSITORY = 'nouuur/timesheet'
        IMAGE_TAG         = "${BUILD_NUMBER}"
        DOCKER_IMAGE      = "${DOCKER_REPOSITORY}:${BUILD_NUMBER}"

        // Kubernetes
        K8S_NAMESPACE     = 'timesheet-platform'

        // Application
        APP_PORT          = '8082'
        APP_CONTEXT_PATH  = '/timesheet-devops'
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
                    echo "Java:"
                    java -version

                    echo ""
                    echo "Maven:"
                    mvn -version

                    echo ""
                    echo "Docker:"
                    docker --version

                    echo ""
                    echo "kubectl:"
                    kubectl version --client

                    echo ""
                    echo "Trivy:"
                    trivy --version

                    echo ""
                    echo "Git:"
                    git --version

                    echo ""
                    echo "Pre-commit:"
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

                echo "======================================"
                echo "       CHECKOUT FROM GITHUB"
                echo "======================================"

                checkout([
                    $class: 'GitSCM',

                    branches: [
                        [name: '*/master']
                    ],

                    userRemoteConfigs: [[
                        url: 'https://github.com/nour-messaoudi/timesheet-project.git',
                        credentialsId: 'github-token'
                    ]],

                    extensions: [
                        [$class: 'CleanBeforeCheckout']
                    ]
                ])

                sh '''
                    echo ""
                    echo "Current commit:"
                    git log -1 --oneline

                    echo ""
                    echo "Current branch:"
                    git branch --show-current
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
                    echo "         SECRET SECURITY SCAN"
                    echo "======================================"

                    pre-commit run --all-files

                    echo ""
                    echo "Secret security scan completed successfully."
                '''
            }
        }


        // ============================================================
        // 8. PUBLISH / ARCHIVE ARTIFACT
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
        // 9. BUILD DOCKER IMAGE
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

                    echo ""
                    echo "Docker image information:"

                    docker images "${DOCKER_REPOSITORY}" --format \
                        "table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}"
                '''
            }
        }


        // ============================================================
        // 10. TRIVY IMAGE SECURITY SCAN
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
        // 11. PUSH TO DOCKERHUB
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
                        echo "         PUSH TO DOCKERHUB"
                        echo "======================================"

                        echo "Docker repository:"
                        echo "${DOCKER_REPOSITORY}"

                        echo ""
                        echo "Logging in to DockerHub..."

                        echo "${DOCKER_PASSWORD}" | \
                            docker login \
                            -u "${DOCKER_USERNAME}" \
                            --password-stdin

                        echo ""
                        echo "Pushing image:"
                        echo "${DOCKER_IMAGE}"

                        docker push "${DOCKER_IMAGE}"

                        echo ""
                        echo "Docker image pushed successfully."

                        echo ""
                        echo "Logging out from DockerHub..."

                        docker logout
                    '''
                }
            }
        }


        // ============================================================
        // 12. DEPLOY
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
                        echo "            DEPLOY"
                        echo "======================================"

                        echo "Kubernetes namespace:"
                        echo "${K8S_NAMESPACE}"

                        echo ""
                        echo "Creating namespace if necessary..."

                        kubectl apply \
                            -f k8s/namespace.yaml

                        echo ""
                        echo "Creating/updating MySQL Secret..."

                        kubectl create secret generic mysql-secret \
                            -n "${K8S_NAMESPACE}" \
                            --from-literal=MYSQL_USER="${DB_USERNAME}" \
                            --from-literal=MYSQL_PASSWORD="${DB_PASSWORD}" \
                            --dry-run=client \
                            -o yaml | kubectl apply -f -

                        echo ""
                        echo "Deploying MySQL..."

                        kubectl apply \
                            -f k8s/mysql-pvc.yaml \
                            -f k8s/mysql-deployment.yaml \
                            -f k8s/mysql-service.yaml

                        echo ""
                        echo "Deploying Timesheet application..."

                        kubectl apply \
                            -f k8s/timesheet-deployment.yaml \
                            -f k8s/timesheet-service.yaml

                        echo ""
                        echo "Deploying Prometheus..."

                        kubectl apply \
                            -f k8s/prometheus-configmap.yaml \
                            -f k8s/prometheus-deployment.yaml \
                            -f k8s/prometheus-service.yaml

                        echo ""
                        echo "Deploying Grafana if manifests exist..."

                        if [ -f k8s/grafana-deployment.yaml ] && \
                           [ -f k8s/grafana-service.yaml ]; then

                            kubectl apply \
                                -f k8s/grafana-deployment.yaml \
                                -f k8s/grafana-service.yaml
                        else
                            echo "Grafana manifests not found. Skipping."
                        fi

                        echo ""
                        echo "Updating Timesheet image..."

                        kubectl set image \
                            deployment/timesheet \
                            timesheet="${DOCKER_IMAGE}" \
                            -n "${K8S_NAMESPACE}"

                        echo ""
                        echo "Waiting for Timesheet deployment..."

                        kubectl rollout status \
                            deployment/timesheet \
                            -n "${K8S_NAMESPACE}" \
                            --timeout=180s

                        echo ""
                        echo "Deployment completed successfully."
                    '''
                }
            }
        }


        // ============================================================
        // 13. HEALTH CHECK
        // ============================================================

        stage('HEALTH CHECK') {
            steps {

                sh '''
                    set -e

                    echo "======================================"
                    echo "           HEALTH CHECK"
                    echo "======================================"

                    echo ""
                    echo "=== Kubernetes Pods ==="

                    kubectl get pods \
                        -n "${K8S_NAMESPACE}" \
                        -o wide

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
                    echo "=== Timesheet Application Health ==="

                    wget -qO- \
                        "http://localhost:${APP_PORT}${APP_CONTEXT_PATH}/actuator/health"

                    echo ""

                    echo "Checking application status..."

                    wget -qO- \
                        "http://localhost:${APP_PORT}${APP_CONTEXT_PATH}/actuator/health" \
                        | grep '"status":"UP"'

                    echo ""
                    echo "Timesheet application is healthy."

                    echo ""
                    echo "=== Prometheus Health ==="

                    wget -qO- \
                        "http://localhost:9090/-/healthy"

                    echo ""
                    echo "Prometheus is healthy."

                    echo ""
                    echo "======================================"
                    echo "        HEALTH CHECK PASSED"
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

            echo '''
======================================
          PIPELINE SUCCESS
======================================

Job: timesheet-project
Build: #${BUILD_NUMBER}
Result: SUCCESS

Docker Image:
${DOCKER_IMAGE}

Kubernetes Namespace:
${K8S_NAMESPACE}

All pipeline stages completed successfully.
'''
        }


        failure {

            echo '''
======================================
          PIPELINE FAILURE
======================================

Job: timesheet-project
Build: #${BUILD_NUMBER}
Result: FAILURE

Docker Image:
${DOCKER_IMAGE}

Kubernetes Namespace:
${K8S_NAMESPACE}

Please check the Jenkins console output
to identify the failed stage.
'''
        }


        always {

            echo '''
======================================
          PIPELINE SUMMARY
======================================

Job:
${JOB_NAME}

Build:
#${BUILD_NUMBER}

Result:
${currentBuild.currentResult}

Docker Image:
${DOCKER_IMAGE}

Kubernetes Namespace:
${K8S_NAMESPACE}

Build URL:
${BUILD_URL}
======================================
'''
        }
    }
}
