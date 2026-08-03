package handlers

import "testing"

// A share on a mergerfs mount presents the UNION, not the dataset the union's
// mountpoint happens to sit on — linking to that dataset would draw a
// dependency the share does not have.
func TestBackingIDsPrefersTheUnionForSharesOnIt(t *testing.T) {
	dsByMount := map[string]string{
		"/mnt/tank":       "ds:tank",
		"/mnt/tank/media": "ds:tank/media",
	}
	mfsByMount := map[string]string{"/mnt/union": "mfs:media"}

	ds, mfs := backingIDs(dsByMount, mfsByMount, "/mnt/union/movies")
	if len(mfs) != 1 || mfs[0] != "mfs:media" {
		t.Errorf("share on a union did not resolve to it: ds=%v mfs=%v", ds, mfs)
	}
	if len(ds) != 0 {
		t.Errorf("share on a union also linked a dataset: %v", ds)
	}

	// A plain dataset share is untouched.
	ds, mfs = backingIDs(dsByMount, mfsByMount, "/mnt/tank/media")
	if len(ds) != 1 || ds[0] != "ds:tank/media" || len(mfs) != 0 {
		t.Errorf("dataset share mis-resolved: ds=%v mfs=%v", ds, mfs)
	}

	// The deeper mount wins: a dataset mounted INSIDE a union's mountpoint is
	// its own thing, not the union.
	dsByMount["/mnt/union/scratch"] = "ds:tank/scratch"
	ds, mfs = backingIDs(dsByMount, mfsByMount, "/mnt/union/scratch/x")
	if len(ds) != 1 || ds[0] != "ds:tank/scratch" || len(mfs) != 0 {
		t.Errorf("deeper dataset lost to the union: ds=%v mfs=%v", ds, mfs)
	}

	// No match at all → nothing linked, rather than a wrong guess.
	if ds, mfs = backingIDs(dsByMount, mfsByMount, "/srv/elsewhere"); len(ds)+len(mfs) != 0 {
		t.Errorf("unrelated path linked something: ds=%v mfs=%v", ds, mfs)
	}
}

func TestPoolIDOfDatasetID(t *testing.T) {
	cases := map[string]string{
		"ds:tank":            "pool:tank",
		"ds:tank/media/kids": "pool:tank",
		"pool:tank":          "",
		"":                   "",
	}
	for in, want := range cases {
		if got := poolIDOfDatasetID(in); got != want {
			t.Errorf("poolIDOfDatasetID(%q) = %q, want %q", in, got, want)
		}
	}
}
