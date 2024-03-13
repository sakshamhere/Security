# Sonatype Nexus
https://www.youtube.com/watch?v=JilcY0eqMFE

Sonatype is the name of company who provided Nexus software

# What is Nexus (Build Artifacts & Repository Manager)

Nexus by Sonatype is a repository manager that organizes, stores and distributes artifacts needed for development. 

With Nexus, developers can completely control access to, and deployment of, every artifact in an organization from a single location, making it easier to distribute software. 

It is most commonly used for hosting Apache Maven. Currently it supports Maven/Java, npm, NuGet, RubyGems, Docker, P2, OBR, APT and YUM and more.


The above video is best, so what I understood is that since Maven fetches from Maven Central Repo which is public on Internet, so internal user should not have direct access to that to fetch, 

so Nexus acts as proxy and fetches on behalf, similarly for other public repo like Docker hub etc

# At its core Repository Manager does the following

1. Store and retrive build artifacts
2. Proxies remote repositories and caches content
3. Hosts Internal Repositories
4. Groups repositories into single repo
5. Enable greater collaboration between developers
6. Brings increased build performance
7. Reduce network bandwidth and dependency on remote repo by cachingdata
7. Reduce network bandwidth and dependency on remote repo by cachingdata
7. Reduce network bandwidth and dependency on remote repo by cachingdata


