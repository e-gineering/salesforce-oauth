
For deploying a snapshot (it will use the current project version, which should always be a x-SNAPSHOT version) to the maven repository:
```
mvn deploy
```

To perform a release:
```
mvn release:prepare release:perform --batch-mode
```
This will remove the `-SNAPSHOT` suffix from the version, commit, create a tag for that version and increment the version for a new `-SNAPSHOT` version for development. It will then checkout the tag and perform a deploy to the maven repo.
