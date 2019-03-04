package influxdb

import (
	"context"
)

type DocumentService interface {
	CreateDocumentStore(ctx context.Context, name string) (DocumentStore, error)
	FindDocumentStore(ctx context.Context, name string) (DocumentStore, error)
}

type Document struct {
	ID   ID           `json:"id"`
	Meta DocumentMeta `json:"meta"`
	Data interface{}  `json:"data,omitempty"` // TODO(desa): maybe this needs to be json.Marshaller & json.Unmarshaler
}

type DocumentMeta struct {
	Name string `json:"name"`
}

type DocumentStore interface {
	CreateDocument(ctx context.Context, d *Document, opts ...DocumentCreateOptions) error
	UpdateDocument(ctx context.Context, d *Document, opts ...DocumentCreateOptions) error

	FindDocuments(ctx context.Context, opts ...DocumentFindOptions) ([]*Document, error)
	DeleteDocuments(ctx context.Context, opts ...DocumentFindOptions) error
}

type DocumentIndex interface {
	AddDocumentOwner(docID ID, ownerType string, ownerID ID) error
	RemoveDocumentOwner(docID ID, ownerType string, ownerID ID) error

	GetAccessorsDocuments(ownerType string, ownerID ID) ([]ID, error)
	GetDocumentsAccessors(docID ID) ([]ID, error)

	UsersOrgs(userID ID) ([]ID, error)
	IsOrgAccessor(userID, orgID ID) error

	// TODO(desa): do we want to keep this one?
	FindOrganizationByName(n string) (ID, error)
}

type DocumentCreateOptions func(ID, DocumentIndex) error

type DocumentFindOptions func(DocumentIndex) ([]ID, error)

func WithOrg(org string) func(ID, DocumentIndex) error {
	return func(id ID, idx DocumentIndex) error {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return err
		}

		return idx.AddDocumentOwner(id, "org", oid)
	}
}

func Authorized(a Authorizer) func(ID, DocumentIndex) error {
	switch t := a.(type) {
	case *Authorization:
		return TokenAuthorized(t)
	}

	return func(docID ID, idx DocumentIndex) error {
		oids, err := idx.GetDocumentsAccessors(docID)
		if err != nil {
			return err
		}

		for _, oid := range oids {
			if err := idx.IsOrgAccessor(a.GetUserID(), oid); err == nil {
				return nil
			}
		}

		return &Error{
			Code: EUnauthorized,
			Msg:  "authorizer cannot access document",
		}
	}
}

func TokenAuthorized(a *Authorization) func(ID, DocumentIndex) error {
	return func(id ID, idx DocumentIndex) error {
		if !a.IsActive() {
			return &Error{
				Code: EUnauthorized,
				Msg:  "authorizer cannot access document",
			}
		}

		oids, err := idx.GetDocumentsAccessors(id)
		if err != nil {
			return err
		}
		orgs := map[ID]bool{}
		for _, oid := range oids {
			orgs[oid] = true
		}

		for _, p := range a.Permissions {
			if p.Action == ReadAction {
				continue
			}

			// If the authz has a direct permission to access the resource
			if p.Resource.Type == DocumentsResourceType && p.Resource.ID != nil && *p.Resource.ID == id {
				return nil
			}
			// If the authz has a direct permission to access the class of resources
			if p.Resource.Type == DocumentsResourceType && p.Resource.ID == nil && p.Resource.OrgID == nil {
				return nil
			}

			if p.Resource.Type == DocumentsResourceType && p.Resource.OrgID != nil && orgs[*p.Resource.OrgID] {
				return nil
			}

		}

		return &Error{
			Code: EUnauthorized,
			Msg:  "authorization cannot access document",
		}
	}
}

func AuthorizedWithOrg(a Authorizer, org string) func(ID, DocumentIndex) error {
	switch t := a.(type) {
	case *Authorization:
		return TokenAuthorizedWithOrg(t, org)
	}

	return func(id ID, idx DocumentIndex) error {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return err
		}

		if err := idx.IsOrgAccessor(a.GetUserID(), oid); err != nil {
			return err
		}

		return idx.AddDocumentOwner(id, "org", oid)
	}
}

func TokenAuthorizedWithOrg(a *Authorization, org string) func(ID, DocumentIndex) error {
	return func(id ID, idx DocumentIndex) error {
		if !a.IsActive() {
			return &Error{
				Code: EUnauthorized,
				Msg:  "authorization cannot add org as document owner",
			}
		}

		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return err
		}

		p := Permission{
			Action: WriteAction,
			Resource: Resource{
				Type:  DocumentsResourceType,
				OrgID: &oid,
			},
		}

		if !a.Allowed(p) {
			return &Error{
				Code: EUnauthorized,
				Msg:  "authorization cannot add org as document owner",
			}
		}

		return idx.AddDocumentOwner(id, "org", oid)
	}
}

func WhereOrg(org string) func(DocumentIndex) ([]ID, error) {
	return func(idx DocumentIndex) ([]ID, error) {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return nil, err
		}
		return idx.GetAccessorsDocuments("org", oid)
	}
}

func AuthorizedWhereOrg(a Authorizer, org string) func(DocumentIndex) ([]ID, error) {
	switch t := a.(type) {
	case *Authorization:
		return TokenAuthorizedWhereOrg(t, org)
	}

	return func(idx DocumentIndex) ([]ID, error) {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return nil, err
		}

		if err := idx.IsOrgAccessor(a.GetUserID(), oid); err != nil {
			return nil, err
		}

		return idx.GetAccessorsDocuments("org", oid)
	}
}

func TokenAuthorizedWhereOrg(a *Authorization, org string) func(DocumentIndex) ([]ID, error) {
	return func(idx DocumentIndex) ([]ID, error) {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return nil, err
		}

		p := Permission{
			// TODO(desa): this should be configurable, but should be sufficient for now.
			Action: ReadAction,
			Resource: Resource{
				Type:  OrgsResourceType,
				OrgID: &oid,
			},
		}

		if !a.Allowed(p) {
			return nil, &Error{
				Code: EUnauthorized,
				Msg:  "authorizer cannot access documents",
			}
		}

		return idx.GetAccessorsDocuments("org", oid)
	}
}

func AuthorizedWhere(a Authorizer) func(DocumentIndex) ([]ID, error) {
	switch t := a.(type) {
	case *Authorization:
		return TokenAuthorizedWhere(t)
	}

	var ids []ID
	return func(idx DocumentIndex) ([]ID, error) {
		dids, err := idx.GetAccessorsDocuments("user", a.GetUserID())
		if err != nil {
			return nil, err
		}

		ids = append(ids, dids...)

		orgIDs, err := idx.UsersOrgs(a.GetUserID())
		if err != nil {
			return nil, err
		}

		for _, orgID := range orgIDs {
			dids, err := idx.GetAccessorsDocuments("org", orgID)
			if err != nil {
				return nil, err
			}

			ids = append(ids, dids...)
		}

		return ids, nil
	}
}

func TokenAuthorizedWhere(a *Authorization) func(DocumentIndex) ([]ID, error) {
	// TODO(desa): what to do about retrieving all documents using auth? (e.g. write/read:documents)
	var ids []ID
	return func(idx DocumentIndex) ([]ID, error) {
		if !a.IsActive() {
			return nil, &Error{
				Code: EUnauthorized,
				Msg:  "authorizer cannot access documents",
			}
		}

		for _, p := range a.Permissions {
			if p.Resource.Type == DocumentsResourceType && p.Resource.OrgID != nil {
				oids, err := idx.GetAccessorsDocuments("org", *p.Resource.OrgID)
				if err != nil {
					return nil, err
				}
				ids = append(ids, oids...)
			}

			if p.Resource.Type == DocumentsResourceType && p.Resource.ID != nil {
				ids = append(ids, *p.Resource.ID)
			}
		}

		return ids, nil
	}
}

func WhereID(docID ID) func(DocumentIndex) ([]ID, error) {
	return func(idx DocumentIndex) ([]ID, error) {
		return []ID{docID}, nil
	}
}

func AuthorizedWhereID(a Authorizer, docID ID) func(DocumentIndex) ([]ID, error) {
	switch t := a.(type) {
	case *Authorization:
		return TokenAuthorizedWhereID(t, docID)
	}

	return func(idx DocumentIndex) ([]ID, error) {
		oids, err := idx.GetDocumentsAccessors(docID)
		if err != nil {
			return nil, err
		}

		for _, oid := range oids {
			if err := idx.IsOrgAccessor(a.GetUserID(), oid); err == nil {
				return []ID{docID}, nil
			}
		}

		return nil, &Error{
			Code: EUnauthorized,
			Msg:  "authorizer cannot access document",
		}
	}
}

func TokenAuthorizedWhereID(a *Authorization, docID ID) func(DocumentIndex) ([]ID, error) {
	return func(idx DocumentIndex) ([]ID, error) {
		if !a.IsActive() {
			return nil, &Error{
				Code: EUnauthorized,
				Msg:  "authorizer cannot access documents",
			}
		}

		oids, err := idx.GetDocumentsAccessors(docID)
		if err != nil {
			return nil, err
		}
		orgs := map[ID]bool{}
		for _, oid := range oids {
			orgs[oid] = true
		}

		for _, p := range a.Permissions {
			// If the authz has a direct permission to access the resource
			if p.Resource.Type == DocumentsResourceType && p.Resource.ID != nil && docID == *p.Resource.ID {
				return []ID{docID}, nil
			}
			// If the authz has a direct permission to access the class of resources
			if p.Resource.Type == DocumentsResourceType && p.Resource.ID == nil && p.Resource.OrgID == nil {
				return []ID{docID}, nil
			}

			if p.Resource.Type == DocumentsResourceType && p.Resource.OrgID != nil && orgs[*p.Resource.OrgID] {
				return []ID{docID}, nil
			}
		}

		return nil, &Error{
			Code: EUnauthorized,
			Msg:  "authorization cannot access document",
		}
	}
}
