import eu.jameshamilton.log4shell.check
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.spyk
import io.mockk.verify
import proguard.classfile.AccessConstants.PRIVATE
import proguard.classfile.AccessConstants.PUBLIC
import proguard.classfile.ClassPool
import proguard.classfile.Clazz
import proguard.classfile.Member
import proguard.classfile.ProgramClass
import proguard.classfile.ProgramMember
import proguard.classfile.VersionConstants.CLASS_VERSION_1_6
import proguard.classfile.editor.ClassBuilder
import proguard.classfile.util.ClassRenamer
import proguard.classfile.visitor.MemberVisitor

class Log4ShellDetectorTest : FunSpec({
    val jndiLookup = ClassBuilder(
        CLASS_VERSION_1_6,
        PUBLIC,
        "org/apache/logging/log4j/core/lookup/JndiLookup",
        "java/lang/Object",
    ).programClass

    val jndiManager = ClassBuilder(
        CLASS_VERSION_1_6,
        PUBLIC,
        "org/apache/logging/log4j/core/net/JndiManager",
        "java/lang/Object",
    ).apply {
        addMethod(PRIVATE, "<init>", "(Ljava/lang/String;Ljavax/naming/Context;)V")
    }.programClass

    test("Should not detect Log4Shell if JndiLookup is not present") {
        val programClassPool = ClassPool()
        val visitor = spyk(object : MemberVisitor {
            override fun visitAnyMember(clazz: Clazz, member: Member) {}
        })

        check(programClassPool, visitor)

        verify(exactly = 0) {
            visitor.visitProgramMember(
                ofType(ProgramClass::class),
                ofType(ProgramMember::class)
            )
        }
    }

    test("Should detect Log4Shell if JndiLookup and old constructor is present") {
        val programClassPool = ClassPool(jndiLookup, jndiManager)
        val visitor = spyk(object : MemberVisitor {
            override fun visitAnyMember(clazz: Clazz, member: Member) {}
        })

        check(programClassPool, visitor)

        verify(exactly = 1) {
            visitor.visitProgramMember(
                ofType(ProgramClass::class),
                ofType(ProgramMember::class)
            )
        }
    }

    test("Should detect shadowed log4j if JndiLookup and old constructor is present") {
        val programClassPool = ClassPool(jndiLookup, jndiManager).apply {
            classesAccept(
                ClassRenamer {
                    "com/example/shadow/${it.name}"
                }
            )
        }

        programClassPool.getClass("org/apache/logging/log4j/core/lookup/JndiLookup")
            .name shouldBe "com/example/shadow/org/apache/logging/log4j/core/lookup/JndiLookup"

        programClassPool.getClass("org/apache/logging/log4j/core/net/JndiManager")
            .name shouldBe "com/example/shadow/org/apache/logging/log4j/core/net/JndiManager"

        val visitor = spyk(object : MemberVisitor {
            override fun visitAnyMember(clazz: Clazz, member: Member) {}
        })
        check(programClassPool, visitor)

        verify(exactly = 1) {
            visitor.visitProgramMember(
                ofType(ProgramClass::class),
                ofType(ProgramMember::class)
            )
        }
    }

    test("Should not detect Log4Shell if old constructor is present but JndiLookup is not present") {
        // Removing JndiLookup is a workaround for log4shell
        val programClassPool = ClassPool(jndiManager)
        val visitor = spyk(object : MemberVisitor {
            override fun visitAnyMember(clazz: Clazz, member: Member) {}
        })

        check(programClassPool, visitor)

        verify(exactly = 0) {
            visitor.visitProgramMember(
                ofType(ProgramClass::class),
                ofType(ProgramMember::class)
            )
        }
    }
})
