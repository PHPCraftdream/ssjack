package ownerresource

import (
	"context"
	"testing"
)

func TestAbsentResourcesRefuseWithoutOpeningInstallation(t *testing.T) {
	if resource, err := Open(context.Background(), nil); err == nil || resource != nil {
		t.Fatal("missing link acquired installation authority")
	}
	var resource *Resources
	if err := resource.Check(); err == nil {
		t.Fatal("missing resources passed the installation check")
	}
	if err := resource.OpenEditor(context.Background()); err == nil {
		t.Fatal("missing resources opened an editor")
	}
	resource.ResetEditor()
	resource.Close()
}
