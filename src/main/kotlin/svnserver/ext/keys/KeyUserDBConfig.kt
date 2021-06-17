/*
 * This file is part of git-as-svn. It is subject to the license terms
 * in the LICENSE file found in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/gpl-2.0.html. No part of git-as-svn,
 * including this file, may be copied, modified, propagated, or distributed
 * except according to the terms contained in the LICENSE file.
 */
package svnserver.ext.keys

import svnserver.Loggers
import svnserver.auth.UserDB
import svnserver.config.UserDBConfig
import svnserver.context.SharedContext
import java.nio.file.Files
import java.nio.file.Path
import javax.crypto.spec.SecretKeySpec

class KeyUserDBConfig : UserDBConfig {
    private var userDB: UserDBConfig? = null
    private var sshKeysToken: String? = null
    private var sshKeysTokenFile: String? = null

    @Throws(Exception::class)
    override fun create(context: SharedContext): UserDB {
        val internal = userDB!!.create(context)
        var key: SecretKeySpec? = null

        sshKeysTokenFile?.let { p ->
            key = SecretKeySpec(Files.readAllBytes(Path.of(p)), "RAW")
        } ?: sshKeysToken?.let { s ->
            key = SecretKeySpec(s.toByteArray(), "RAW")
        } ?: run {
            log.warn("Neither sshKeysTokenFile no sshKeysToken has been specified. Authentication will never succeed.")
        }

        return KeyUserDB(internal, key)
    }

    companion object {
        private val log = Loggers.ssh
    }
}
