package eu.jameshamilton.log4shell

import proguard.classfile.AccessConstants.PRIVATE
import proguard.classfile.ClassPool
import proguard.classfile.Clazz
import proguard.classfile.Member
import proguard.classfile.util.ClassReferenceInitializer
import proguard.classfile.util.ClassSubHierarchyInitializer
import proguard.classfile.util.ClassSuperHierarchyInitializer
import proguard.classfile.util.WarningPrinter
import proguard.classfile.visitor.AllMemberVisitor
import proguard.classfile.visitor.ClassCounter
import proguard.classfile.visitor.ClassNameFilter
import proguard.classfile.visitor.ClassVisitor
import proguard.classfile.visitor.ConstructorMethodFilter
import proguard.classfile.visitor.MemberAccessFilter
import proguard.classfile.visitor.MemberCounter
import proguard.classfile.visitor.MemberDescriptorFilter
import proguard.classfile.visitor.MemberVisitor
import proguard.classfile.visitor.MethodFilter
import proguard.classfile.visitor.MultiMemberVisitor
import proguard.io.DataEntry
import proguard.io.DataEntryNameFilter
import proguard.io.DataEntryReader
import proguard.io.Dex2JarReader
import proguard.io.DirectorySource
import proguard.io.FileDataEntry
import proguard.io.FilteredDataEntryReader
import proguard.io.JarReader
import proguard.io.NameFilteredDataEntryReader
import proguard.io.ZipFileDataEntry
import proguard.util.ExtensionMatcher
import proguard.util.OrMatcher
import java.io.File
import proguard.classfile.visitor.ClassPoolFiller as ProGuardClassPoolFiller
import proguard.io.ClassReader as ProGuardClassReader

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: log4shell-detector <jar-file>")
        return
    }

    val input = File(args.first())
    val programClassPool = readInput(input)

    check(programClassPool) { locations ->
        println(
            """
            |WARNING: log4j < 2.15.0 vulnerable to CVE-2021-44228 found in:
            |${locations.joinToString(separator = "\n") { "\t- $it" }}
            |
            |For more information see: https://logging.apache.org/log4j/2.x/security.html
            """.trimMargin()
        )
    }
}

fun check(programClassPool: ClassPool, onDetected: (Set<String>) -> Unit) = check(
    programClassPool,
    object : MemberVisitor {
        @Suppress("UNCHECKED_CAST")
        private fun processingInfoToLocation(clazz: Clazz): Set<String> = when (clazz.processingInfo) {
            is DataEntry -> with(clazz.processingInfo as DataEntry) {
                setOf(this.parent?.originalName ?: this.originalName)
            }
            is Set<*> -> (clazz.processingInfo as Set<DataEntry>).map {
                when (it) {
                    is FileDataEntry -> it.file.absolutePath
                    is ZipFileDataEntry -> it.parent.originalName
                    else -> it.originalName
                }
            }.toSortedSet()
            else -> setOf("unknown")
        }

        override fun visitAnyMember(clazz: Clazz, member: Member) {
            onDetected(processingInfoToLocation(clazz))
        }
    }
)

fun check(programClassPool: ClassPool, jndiManagerOldConstructorVisitor: MemberVisitor) {
    val jndiLookupCounter = ClassCounter()
    val jndiManagerOldConstructorCounter = MemberCounter()

    // A workaround for CVE-2021-44228 is to remove the `JndiLookup` class,
    // so check that exists first. https://www.kb.cert.org/vuls/id/930724#workarounds
    //
    // Prefix with `**` to take into account shadow packing.
    programClassPool.classesAccept("**org/apache/logging/log4j/core/lookup/JndiLookup", jndiLookupCounter)

    if (jndiLookupCounter.count > 0) {
        // Versions prior to 2.15.0 have the following constructor in JndiManager:
        // private <init>(Ljava/lang/String;Ljavax/naming/Context;)V
        //
        // https://github.com/apache/logging-log4j2/blob/rel/2.14.1/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java
        //
        // Based on Yara rule https://github.com/darkarnium/Log4j-CVE-Detect/blob/main/rules/vulnerability/log4j/CVE-2021-44228.yar

        programClassPool.classesAccept(
            ClassNameFilter(
                // Prefix with `**` to take into account shadow packing.
                "**org/apache/logging/log4j/core/net/JndiManager",
                AllMemberVisitor(
                    MethodFilter(
                        ConstructorMethodFilter(
                            MemberAccessFilter(
                                /* requiredSetAccessFlags = */ PRIVATE, /* requiredUnsetAccessFlags = */ 0,
                                MemberDescriptorFilter(
                                    "(Ljava/lang/String;Ljavax/naming/Context;)V",
                                    MultiMemberVisitor(
                                        jndiManagerOldConstructorCounter,
                                        jndiManagerOldConstructorVisitor
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }

    if (jndiManagerOldConstructorCounter.count == 0 && jndiLookupCounter.count > 0) {
        println(
            """
            JndiLookup class found, but no pre-2.15.0 constructor found.
            """.trimIndent()
        )
    }
}

private fun readInput(inputFile: File): ClassPool {
    val programClassPool = ClassPool()
    var classReader: DataEntryReader = NameFilteredDataEntryReader(
        "**.class",
        ClassReader(
            isLibrary = false,
            skipNonPublicLibraryClasses = false,
            skipNonPublicLibraryClassMembers = false,
            ignoreStackMapAttributes = false,
            warningPrinter = null,
            classVisitor = ProcessingInfoMergingClassPoolFiller(programClassPool)
        )
    )

    classReader = NameFilteredDataEntryReader(
        "classes*.dex",
        Dex2JarReader(
            false,
            classReader
        ),
        classReader
    )

    classReader = FilteredDataEntryReader(
        DataEntryNameFilter(ExtensionMatcher(".aar")),
        JarReader(
            NameFilteredDataEntryReader(
                "classes.jar",
                JarReader(classReader)
            )
        ),
        FilteredDataEntryReader(
            DataEntryNameFilter(
                OrMatcher(
                    ExtensionMatcher(".jar"),
                    ExtensionMatcher(".war"),
                    ExtensionMatcher(".zip"),
                    ExtensionMatcher(".apk")
                )
            ),
            JarReader(classReader),
            classReader
        )
    )

    DirectorySource(inputFile).pumpDataEntries {
        try {
            classReader.read(it)
        } catch (e: Exception) {
            println("ERROR: Failed to read '${it.name}'")
        }
    }

    return programClassPool
}

class ClassReader(
    isLibrary: Boolean,
    skipNonPublicLibraryClasses: Boolean,
    skipNonPublicLibraryClassMembers: Boolean,
    ignoreStackMapAttributes: Boolean,
    warningPrinter: WarningPrinter?,
    private val classVisitor: ClassVisitor
) : DataEntryReader {
    private lateinit var currentDataEntry: DataEntry

    private val proguardClassReader = ProGuardClassReader(
        isLibrary,
        skipNonPublicLibraryClasses,
        skipNonPublicLibraryClassMembers,
        ignoreStackMapAttributes,
        warningPrinter
    ) {
        it.processingInfo = currentDataEntry
        it.accept(classVisitor)
    }

    override fun read(dataEntry: DataEntry) {
        currentDataEntry = dataEntry
        proguardClassReader.read(dataEntry)
    }
}

class ProcessingInfoMergingClassPoolFiller(private val classPool: ClassPool) : ProGuardClassPoolFiller(classPool) {
    @Suppress("UNCHECKED_CAST")
    override fun visitAnyClass(clazz: Clazz) {
        when (val existingClazz = classPool.getClass(clazz.name)) {
            is Clazz -> {
                val oldProcessingInfo = existingClazz.processingInfo as MutableSet<DataEntry>
                val newProcessingInfo = clazz.processingInfo
                oldProcessingInfo.add(newProcessingInfo as DataEntry)
            }
            else -> classPool.addClass(clazz.apply { processingInfo = mutableSetOf(processingInfo as DataEntry) })
        }
    }
}

@Suppress("unused") // not required in this app
fun initialize(programClassPool: ClassPool, libraryClassPool: ClassPool) {
    val classReferenceInitializer = ClassReferenceInitializer(programClassPool, libraryClassPool)
    val classSuperHierarchyInitializer = ClassSuperHierarchyInitializer(programClassPool, libraryClassPool)
    val classSubHierarchyInitializer = ClassSubHierarchyInitializer()

    programClassPool.classesAccept(classSuperHierarchyInitializer)
    libraryClassPool.classesAccept(classSuperHierarchyInitializer)

    programClassPool.classesAccept(classReferenceInitializer)
    libraryClassPool.classesAccept(classReferenceInitializer)

    programClassPool.accept(classSubHierarchyInitializer)
    libraryClassPool.accept(classSubHierarchyInitializer)
}
