pipeline {
  agent any
  environment {
    DOCKER_IMAGE = "beewaf:${env.BUILD_NUMBER ?: 'latest'}"
    DOCKER_REGISTRY = "${env.DOCKER_REGISTRY ?: ''}"
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }
    stage('Install') {
      steps {
        sh 'python3 -m venv .venv || true'
        sh '. .venv/bin/activate && pip install -U pip || true'
        sh '. .venv/bin/activate && pip install -r requirements.txt || true'
      }
    }
    stage('Unit Tests') {
      steps {
        sh '. .venv/bin/activate && pytest -q'
      }
    }
    stage('Build Docker Image') {
      steps {
        sh "docker build -t ${DOCKER_IMAGE} -f Dockerfile.full ."
      }
    }
    stage('Integration Test') {
      steps {
        sh "docker rm -f beewaf_ci || true"
        sh "docker run -d --name beewaf_ci -p 8000:8000 ${DOCKER_IMAGE} || true"
        sh 'sleep 5'
        sh './tests/test_waf.sh || true'
        sh "docker rm -f beewaf_ci || true"
      }
    }
    stage('Push Image') {
      when {
        expression { return env.DOCKER_REGISTRY?.trim() }
      }
      steps {
        withCredentials([string(credentialsId: 'docker-registry-credentials', variable: 'DOCKER_PASS')]) {
          sh 'echo "$DOCKER_PASS" | docker login $DOCKER_REGISTRY -u $DOCKER_USER --password-stdin'
          sh "docker tag ${DOCKER_IMAGE} $DOCKER_REGISTRY/${DOCKER_IMAGE}"
          sh "docker push $DOCKER_REGISTRY/${DOCKER_IMAGE}"
        }
      }
    }
    stage('Deploy to Kubernetes') {
      when {
        expression { return fileExists('k8s/deployment.yaml') && env.KUBECONFIG }
      }
      steps {
        sh 'kubectl apply -f k8s/deployment.yaml'
        sh 'kubectl apply -f k8s/service.yaml'
      }
    }
  }
  post {
    always {
      sh 'docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}" | head -n 20 || true'
    }
  }
}
