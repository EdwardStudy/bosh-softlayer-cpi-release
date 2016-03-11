package action

import (
	bosherr "github.com/cloudfoundry/bosh-utils/errors"

	bslcstem "github.com/cloudfoundry/bosh-softlayer-cpi/softlayer/stemcell"
)

type DeleteStemcell struct {
	stemcellFinder bslcstem.Finder
}

func NewDeleteStemcell(stemcellFinder bslcstem.Finder) DeleteStemcell {
	return DeleteStemcell{stemcellFinder: stemcellFinder}
}

func (a DeleteStemcell) Run(stemcellCID StemcellCID) (interface{}, error) {
	stemcell, found, err := a.stemcellFinder.FindById(int(stemcellCID))
	if err != nil {
		return nil, bosherr.WrapErrorf(err, "Finding stemcell '%s'", stemcellCID)
	}

	if found {
		err := stemcell.Delete()
		if err != nil {
			return nil, bosherr.WrapErrorf(err, "Deleting stemcell '%s'", stemcellCID)
		}
	}

	return nil, nil
}
