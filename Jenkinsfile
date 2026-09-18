pipeline {
    agent any

    stages {

        stage('GIT') {
            steps {
                git branch: 'master',
                    credentialsId: 'github-token',
                    url: 'https://github.com/nour-messaoudi/timesheet-project.git'
            }
        }

        stage('BUILD & TEST') {
            steps {
                sh 'mvn clean verify'
            }
        }

        stage('SONARQUBE') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    withCredentials([
                        string(
                            credentialsId: 'sonar-token',
                            variable: 'SONAR_TOKEN'
                        )
                    ]) {
                        sh '''
                            mvn org.sonarsource.scanner.maven:sonar-maven-plugin:5.8.0.7211:sonar \
                            -Dsonar.projectKey=timesheet \
                            -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
                            -Dsonar.token="$SONAR_TOKEN"
                        '''
                    }
                }
            }
        }

        stage('DOCKER BUILD') {
    steps {
        sh 'docker build -t timesheet-project_timesheet:latest .'
    }
}
    }

    post {
        success {
            echo 'Pipeline exécuté avec succès ✅'
        }

        failure {
            echo 'Pipeline échoué ❌'
        }
    }
}
