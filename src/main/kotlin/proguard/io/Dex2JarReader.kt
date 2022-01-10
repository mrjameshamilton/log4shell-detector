/*
 * Converted to Kotlin from the Java version in KotlinMetadataPrinter.
 *
 * ORIGINAL COPYRIGHT NOTICE FOLLOWS:
 *
 * Kotlin metadata printer -- tool to display the Kotlin metadata
 * from Java class files.
 *
 * Copyright (c) 2002-2020 Guardsquare NV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package proguard.io

import com.googlecode.d2j.dex.Dex2jar
import com.googlecode.d2j.reader.DexFileReader
import java.io.File
import java.nio.file.Files
import java.nio.file.Path

/**
 * A DataEntryReader that reads dex files, converts the classes to Java bytecode
 * and delegates the reading of the converted classes to another reader.
 *
 * @author Thomas Neidhart
 */
class Dex2JarReader(private val readCode: Boolean, private val dataEntryReader: DataEntryReader) : DataEntryReader {
    override fun read(dataEntry: DataEntry) {
        // Create a temporary directory for the classes.
        val tempDirectory = Files.createTempDirectory(dataEntry.name)
        val inputStream = dataEntry.inputStream
        val reader = DexFileReader(inputStream)
        Dex2jar.from(reader)
            .skipDebug(!readCode)
            .printIR(false)
            .noCode(!readCode)
            .to(tempDirectory)

        // Delegate to a directory source.
        val directorySource = DirectorySource(tempDirectory.toFile())
        directorySource.pumpDataEntries(dataEntryReader)
        Files.walk(tempDirectory).use { walk ->
            walk.sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete)
        }
    }
}
