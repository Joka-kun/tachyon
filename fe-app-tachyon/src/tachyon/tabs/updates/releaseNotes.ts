import { TachyonShellMethods } from '../../methods';
import type { Tachyon } from '../../types';

// The picker requests five releases per page. Notes look in the latest ten.
const notesPages: Partial<
  Record<Tachyon.ComponentName, Tachyon.ComponentRelease[]>
> = {};

export async function getReleaseForNotes(
  component: Tachyon.ComponentName,
  version: string,
): Promise<Tachyon.ComponentRelease | undefined> {
  const requested = version.trim();
  const tag = requested.replace(/^v/i, '');
  const select = (releases: Tachyon.ComponentRelease[]) =>
    requested
      ? releases.find(
          (release) => release.tag.trim().replace(/^v/i, '') === tag,
        )
      : releases[0];

  if (requested) {
    const cached = select(notesPages[component] ?? []);
    if (cached?.body?.trim()) return cached;
  }

  const response = await TachyonShellMethods.componentListReleases(
    component,
    10,
    1,
  );
  if (!response.success) throw new Error(response.error);
  notesPages[component] = response.data;
  return select(response.data);
}
