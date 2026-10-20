// Writes a bundle dependency record (BUNDLE-METADATA/com.android.tools.build.libraries/
// dependencies.pb) with the Android Gradle Plugin's own generated protobuf classes, then reads it
// back with the same classes and prints what it holds, for msec's reader to be checked against.
//
// Usage: java -cp <gradle-9.4.1.jar>:<protobuf-java-3.25.5.jar>:. WriteDependencies <out.pb> <expected.txt>

import com.android.tools.build.libraries.metadata.AppDependencies;
import com.android.tools.build.libraries.metadata.Library;
import com.android.tools.build.libraries.metadata.LibraryDependencies;
import com.android.tools.build.libraries.metadata.MavenLibrary;
import com.android.tools.build.libraries.metadata.MavenRepo;
import com.android.tools.build.libraries.metadata.ModuleDependencies;
import com.android.tools.build.libraries.metadata.Repository;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int32Value;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public final class WriteDependencies {
    private static Library library(String group, String artifact, String packaging, String classifier,
            String version) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest((group + ":" + artifact + ":" + version).getBytes(StandardCharsets.UTF_8));
        return Library.newBuilder()
                .setMavenLibrary(MavenLibrary.newBuilder()
                        .setGroupId(group)
                        .setArtifactId(artifact)
                        .setPackaging(packaging)
                        .setClassifier(classifier)
                        .setVersion(version))
                .setDigests(Library.Digests.newBuilder().setSha256(ByteString.copyFrom(digest)))
                .setRepoIndex(Int32Value.of(0))
                .build();
    }

    public static void main(String[] args) throws Exception {
        AppDependencies written = AppDependencies.newBuilder()
                .addLibrary(library("androidx.core", "core", "aar", "", "1.15.0"))
                .addLibrary(library("com.squareup.okhttp3", "okhttp", "jar", "", "4.12.0"))
                .addLibrary(library("com.squareup.okio", "okio", "jar", "", "3.9.0"))
                .addLibrary(library("com.google.firebase", "firebase-analytics", "aar", "", "21.6.1"))
                .addLibrary(library("org.jetbrains.kotlin", "kotlin-stdlib", "jar", "", "2.0.21"))
                .addLibrary(library("net.java.dev.jna", "jna", "aar", "android", "5.14.0"))
                .addLibraryDependencies(LibraryDependencies.newBuilder()
                        .setLibraryIndex(1).addLibraryDepIndex(2).addLibraryDepIndex(4))
                .addLibraryDependencies(LibraryDependencies.newBuilder()
                        .setLibraryIndex(0).addLibraryDepIndex(4))
                .addModuleDependencies(ModuleDependencies.newBuilder()
                        .setModuleName("base").addDependencyIndex(0).addDependencyIndex(1)
                        .addDependencyIndex(3).addDependencyIndex(5))
                .addRepositories(Repository.newBuilder()
                        .setMavenRepo(MavenRepo.newBuilder().setUrl("https://dl.google.com/dl/android/maven2/")))
                .build();
        Files.write(Path.of(args[0]), written.toByteArray());

        AppDependencies read = AppDependencies.parseFrom(Files.readAllBytes(Path.of(args[0])));
        List<Integer> direct = new ArrayList<>();
        for (ModuleDependencies module : read.getModuleDependenciesList()) {
            direct.addAll(module.getDependencyIndexList());
        }
        StringBuilder out = new StringBuilder();
        for (int index = 0; index < read.getLibraryCount(); index++) {
            Library library = read.getLibrary(index);
            MavenLibrary maven = library.getMavenLibrary();
            out.append(String.join("\t", "library", Integer.toString(index), maven.getGroupId(),
                    maven.getArtifactId(), maven.getPackaging(), maven.getClassifier(), maven.getVersion(),
                    HexFormat.of().formatHex(library.getDigests().getSha256().toByteArray()),
                    Boolean.toString(direct.contains(index)))).append('\n');
        }
        for (LibraryDependencies edge : read.getLibraryDependenciesList()) {
            List<String> targets = new ArrayList<>();
            for (int target : edge.getLibraryDepIndexList()) {
                targets.add(Integer.toString(target));
            }
            out.append("edge\t").append(edge.getLibraryIndex()).append('\t')
                    .append(String.join(",", targets)).append('\n');
        }
        Files.writeString(Path.of(args[1]), out.toString());
    }
}
