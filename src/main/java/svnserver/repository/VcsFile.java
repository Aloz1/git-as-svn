package svnserver.repository;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.tmatesoft.svn.core.SVNException;
import org.tmatesoft.svn.core.SVNNodeKind;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * Информация о файле.
 *
 * @author a.navrotskiy
 */
public interface VcsFile {
  @NotNull
  String getFileName();

  @NotNull
  String getFullPath();

  @NotNull
  Map<String, String> getProperties(boolean includeInternalProps) throws IOException, SVNException;

  @NotNull
  String getMd5() throws IOException, SVNException;

  long getSize() throws IOException;

  @NotNull
  InputStream openStream() throws IOException;

  boolean isDirectory();

  @NotNull
  SVNNodeKind getKind() throws IOException;

  @NotNull
  Iterable<? extends VcsFile> getEntries() throws IOException, SVNException;

  @Nullable
  VcsFile getEntry(@NotNull String name) throws IOException, SVNException;

  @NotNull
  VcsRevision getLastChange() throws IOException;
}
