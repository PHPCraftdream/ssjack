package appstorecrypto

import (
	"context"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/ownereditor"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

type (
	OwnerEditor = ownereditor.OwnerEditor
	OwnerObject = ownereditor.OwnerObject
)

func NewOwnerEditor(ctx context.Context, installation *Installation, directory *appstorefile.Directory) (*OwnerEditor, error) {
	return ownereditor.NewOwnerEditor(ctx, installation, directory)
}
