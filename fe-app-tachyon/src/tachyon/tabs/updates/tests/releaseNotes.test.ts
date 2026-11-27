import { beforeEach, describe, expect, it, vi } from 'vitest';

const listReleases = vi.hoisted(() => vi.fn());
vi.mock('../../../methods', () => ({
  TachyonShellMethods: { componentListReleases: listReleases },
}));

describe('release notes lookup', () => {
  beforeEach(() => {
    vi.resetModules();
    listReleases.mockReset();
  });

  const latest = { tag: 'v2.1', body: 'Latest changes' };
  const selected = { tag: 'v2.0', body: 'Earlier changes' };

  it('matches the requested tag and reuses its notes for the same component', async () => {
    const { getReleaseForNotes } = await import('../releaseNotes');
    listReleases.mockResolvedValueOnce({
      success: true,
      data: [latest, selected],
    });
    expect(await getReleaseForNotes('tachyon', ' 2.0 ')).toEqual(selected);
    expect(await getReleaseForNotes('tachyon', 'V2.0')).toEqual(selected);
    expect(listReleases.mock.calls).toEqual([['tachyon', 10, 1]]);
  });

  it('only uses the first release when no version was supplied', async () => {
    const { getReleaseForNotes } = await import('../releaseNotes');
    listReleases.mockResolvedValue({ success: true, data: [latest] });
    expect(await getReleaseForNotes('tachyon', selected.tag)).toBeUndefined();
    expect(await getReleaseForNotes('tachyon', '')).toEqual(latest);
  });

  it('asks for the current latest release again after a channel change', async () => {
    const { getReleaseForNotes } = await import('../releaseNotes');
    listReleases
      .mockResolvedValueOnce({ success: true, data: [selected] })
      .mockResolvedValueOnce({ success: true, data: [latest] });
    expect(await getReleaseForNotes('tachyon', '')).toEqual(selected);
    expect(await getReleaseForNotes('tachyon', '')).toEqual(latest);
  });

  it('keeps component caches independent and retries a failed lookup', async () => {
    const { getReleaseForNotes } = await import('../releaseNotes');
    listReleases
      .mockResolvedValueOnce({ success: true, data: [latest] })
      .mockResolvedValueOnce({ success: false, error: 'offline' })
      .mockResolvedValueOnce({ success: true, data: [selected] });
    await getReleaseForNotes('tachyon', '');
    await expect(getReleaseForNotes('tachyon-core', '')).rejects.toThrow(
      'offline',
    );
    expect(await getReleaseForNotes('tachyon-core', '')).toEqual(selected);
  });
});
