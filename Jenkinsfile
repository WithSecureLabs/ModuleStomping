// Build the main project via VS on a windows box
node('windows')
{
    deleteDir()
    checkout([$class: 'GitSCM', branches: [[name: '*/master']], doGenerateSubmoduleConfigurations: false, extensions: [], submoduleCfg: [], userRemoteConfigs: [[credentialsId: '9d40f624-34b5-4993-9520-2ecf8c5996bf', url: 'https://gitlab.countercept.mwr/ahammond/moduleStomping.git']]])

    bat "\"${tool 'msbuildVS2017'}\" cowspot.sln /p:Configuration=Debug /p:Platform=\"x64\" /p:ProductVersion=1.0.0.${env.BUILD_NUMBER}"

    archiveArtifacts 'x64\\Debug\\driver\\*,x64\\**\\*.pdb,x64\\**\\*.exe'
}

// Build the injection payloads on Linux. It's easier than trying to do an unattended install of mingw on windows (!)
node('linux')
{
    sh "apt-get install -y g++-mingw-w64-x86-64 make"
 
    deleteDir()
    checkout([$class: 'GitSCM', branches: [[name: '*/master']], doGenerateSubmoduleConfigurations: false, extensions: [], submoduleCfg: [], userRemoteConfigs: [[credentialsId: '9d40f624-34b5-4993-9520-2ecf8c5996bf', url: 'https://gitlab.countercept.mwr/ahammond/moduleStomping.git']]])

    dir("injectionPayloads")
    {
        sh "make ldscript=ldscript.WindowsCodecsRaw"
        archiveArtifacts '*.dll'
    }
    stash "injectionPayloads"
}

// Now go back to the windows box, and do an injection!
// Try to inject the winsock payload, and test that the required socket is opened.
node('windows')
{
    unstash "injectionPayloads"
    bat returnStatus: true, script: "taskkill /im snippingtool.exe /f"
    bat "start C:\\windows\\system32\\snippingtool.exe"
    bat "x64\\debug\\inject.exe snippingtool.exe injectionPayloads\\winsock.dll WindowsCodecsRaw.dll"
    bat "nc -v -z localhost 27015"
}