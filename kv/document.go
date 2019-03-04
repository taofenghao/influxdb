package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/influxdata/influxdb"
)

const (
	documentDataBucket = "/documents/data"
	documentMetaBucket = "/documents/meta"
)

func (s *Service) CreateDocumentStore(ctx context.Context, ns string) (influxdb.DocumentStore, error) {
	// TODO(desa): keep track of which namespaces exist.
	var ds influxdb.DocumentStore

	err := s.kv.Update(func(tx Tx) error {
		if _, err := tx.Bucket([]byte(path.Join(ns, documentDataBucket))); err != nil {
			return err
		}

		if _, err := tx.Bucket([]byte(path.Join(ns, documentMetaBucket))); err != nil {
			return err
		}

		ds = &DocumentStore{
			namespace: ns,
			service:   s,
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return ds, nil
}

func (s *Service) FindDocumentStore(ctx context.Context, ns string) (influxdb.DocumentStore, error) {
	var ds influxdb.DocumentStore

	err := s.kv.View(func(tx Tx) error {
		if _, err := tx.Bucket([]byte(path.Join(ns, documentDataBucket))); err != nil {
			return err
		}

		if _, err := tx.Bucket([]byte(path.Join(ns, documentMetaBucket))); err != nil {
			return err
		}

		ds = &DocumentStore{
			namespace: ns,
			service:   s,
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return ds, nil
}

type DocumentStore struct {
	service   *Service
	namespace string
}

func (s *DocumentStore) CreateDocument(ctx context.Context, d *influxdb.Document, opts ...influxdb.DocumentCreateOptions) error {
	return s.service.kv.Update(func(tx Tx) error {
		err := s.service.createDocument(ctx, tx, s.namespace, d)
		if err != nil {
			return err
		}

		idx := &DocumentIndex{
			service: s.service,
			tx:      tx,
			ctx:     ctx,
		}
		for _, opt := range opts {
			if err := opt(d.ID, idx); err != nil {
				return err
			}
		}

		return nil
	})
}

type DocumentIndex struct {
	service *Service
	ctx     context.Context
	tx      Tx
}

func (i *DocumentIndex) AddDocumentOwner(id influxdb.ID, ownerType string, ownerID influxdb.ID) error {
	if err := i.ownerExists(ownerType, ownerID); err != nil {
		return err
	}

	m := &influxdb.UserResourceMapping{
		UserID:       ownerID,
		UserType:     influxdb.Owner,
		ResourceType: influxdb.DocumentsResourceType,
		ResourceID:   id,
	}
	return i.service.createUserResourceMapping(i.ctx, i.tx, m)
}

func (i *DocumentIndex) RemoveDocumentOwner(id influxdb.ID, ownerType string, ownerID influxdb.ID) error {
	return i.service.removeDocumentOwner(i.ctx, i.tx, ownerID, id)
}

func WithoutOwners(id influxdb.ID, idx influxdb.DocumentIndex) error {
	ownerIDs, err := idx.GetDocumentsOwners(id)
	if err != nil {
		return err
	}

	for _, ownerID := range ownerIDs {
		if err := idx.RemoveDocumentOwner(id, "org", ownerID); err != nil {
			return err
		}
	}

	return nil
}

func (i *DocumentIndex) UsersOrgs(userID influxdb.ID) ([]influxdb.ID, error) {
	f := influxdb.UserResourceMappingFilter{
		UserID:       userID,
		ResourceType: influxdb.OrgsResourceType,
	}

	ms, err := i.service.findUserResourceMappings(i.ctx, i.tx, f)
	if err != nil {
		return nil, err
	}

	ids := make([]influxdb.ID, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.ResourceID)
	}

	return ids, nil
}

func (i *DocumentIndex) IsOrgOwner(userID influxdb.ID, orgID influxdb.ID) error {
	f := influxdb.UserResourceMappingFilter{
		UserID:       userID,
		ResourceType: influxdb.OrgsResourceType,
		ResourceID:   orgID,
	}

	ms, err := i.service.findUserResourceMappings(i.ctx, i.tx, f)
	if err != nil {
		return err
	}

	for _, m := range ms {
		if m.UserType == influxdb.Owner {
			return nil
		}
	}

	return &influxdb.Error{
		Code: influxdb.EUnauthorized,
		Msg:  "user is not org owner",
	}
}

func (i *DocumentIndex) IsOrgMember(userID influxdb.ID, orgID influxdb.ID) error {
	f := influxdb.UserResourceMappingFilter{
		UserID:       userID,
		ResourceType: influxdb.OrgsResourceType,
		ResourceID:   orgID,
	}

	ms, err := i.service.findUserResourceMappings(i.ctx, i.tx, f)
	if err != nil {
		return err
	}

	for _, m := range ms {
		switch m.UserType {
		case influxdb.Owner, influxdb.Member:
			return nil
		default:
			continue
		}
	}

	return &influxdb.Error{
		Code: influxdb.EUnauthorized,
		Msg:  "user is not org member",
	}
}

func (i *DocumentIndex) ownerExists(ownerType string, ownerID influxdb.ID) error {
	switch ownerType {
	case "org":
		if _, err := i.service.findOrganizationByID(i.ctx, i.tx, ownerID); err != nil {
			return err
		}
	case "user":
		if _, err := i.service.findUserByID(i.ctx, i.tx, ownerID); err != nil {
			return err
		}
	default:
		return &influxdb.Error{
			Code: influxdb.EInternal,
			Msg:  fmt.Sprintf("unknown owner type %q", ownerType),
		}
	}

	return nil
}

func (i *DocumentIndex) FindOrganizationByName(org string) (influxdb.ID, error) {
	o, err := i.service.findOrganizationByName(i.ctx, i.tx, org)
	if err != nil {
		return influxdb.InvalidID(), err
	}
	return o.ID, nil
}

func (i *DocumentIndex) GetDocumentsOwners(docID influxdb.ID) ([]influxdb.ID, error) {
	return i.service.getDocumentsOwners(i.ctx, i.tx, docID)
}

func (i *DocumentIndex) GetOwnersDocuments(ownerType string, ownerID influxdb.ID) ([]influxdb.ID, error) {
	if err := i.ownerExists(ownerType, ownerID); err != nil {
		return nil, err
	}

	f := influxdb.UserResourceMappingFilter{
		UserID:       ownerID,
		UserType:     influxdb.Owner,
		ResourceType: influxdb.DocumentsResourceType,
	}
	ms, err := i.service.findUserResourceMappings(i.ctx, i.tx, f)
	if err != nil {
		return nil, err
	}

	ids := make([]influxdb.ID, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.ResourceID)
	}

	return ids, nil
}

func (s *Service) getDocumentsOwners(ctx context.Context, tx Tx, docID influxdb.ID) ([]influxdb.ID, error) {
	f := influxdb.UserResourceMappingFilter{
		UserType:     influxdb.Owner,
		ResourceType: influxdb.DocumentsResourceType,
		ResourceID:   docID,
	}
	ms, err := s.findUserResourceMappings(ctx, tx, f)
	if err != nil {
		return nil, err
	}

	ids := make([]influxdb.ID, 0, len(ms))
	for _, m := range ms {
		// TODO(desa): this is really an orgID
		ids = append(ids, m.UserID)
	}

	return ids, nil
}

func (s *Service) createDocument(ctx context.Context, tx Tx, ns string, d *influxdb.Document) error {
	d.ID = s.IDGenerator.ID()

	if err := s.putDocument(ctx, tx, ns, d); err != nil {
		return err
	}

	return nil
}

func (s *Service) putDocument(ctx context.Context, tx Tx, ns string, d *influxdb.Document) error {
	if err := s.putDocumentMeta(ctx, tx, ns, d.ID, &d.Meta); err != nil {
		return err
	}

	if err := s.putDocumentData(ctx, tx, ns, d.ID, d.Data); err != nil {
		return err
	}

	// TODO(desa): implement
	//if err := s.indexDocumentMeta(ctx, tx, d.ID, d.Meta); err != nil {
	//}

	return nil
}

func (s *Service) putAtID(ctx context.Context, tx Tx, bucket string, id influxdb.ID, i interface{}) error {
	v, err := json.Marshal(i)
	if err != nil {
		return err
	}

	k, err := id.Encode()
	if err != nil {
		return err
	}

	b, err := tx.Bucket([]byte(bucket))
	if err != nil {
		return err
	}

	if err := b.Put(k, v); err != nil {
		return err
	}

	return nil
}

func (s *Service) putDocumentData(ctx context.Context, tx Tx, ns string, id influxdb.ID, data interface{}) error {
	return s.putAtID(ctx, tx, path.Join(ns, documentDataBucket), id, data)
}

func (s *Service) putDocumentMeta(ctx context.Context, tx Tx, ns string, id influxdb.ID, m *influxdb.DocumentMeta) error {
	return s.putAtID(ctx, tx, path.Join(ns, documentMetaBucket), id, m)
}

func (s *DocumentStore) PutDocument(ctx context.Context, d *influxdb.Document) error {
	return s.service.kv.Update(func(tx Tx) error {
		return s.service.putDocument(ctx, tx, s.namespace, d)
	})
}

func (s *Service) findDocumentsByID(ctx context.Context, tx Tx, ns string, ids ...influxdb.ID) ([]*influxdb.Document, error) {
	ds := make([]*influxdb.Document, 0, len(ids))

	for _, id := range ids {
		d, err := s.findDocumentByID(ctx, tx, ns, id)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

func (s *Service) findDocumentByID(ctx context.Context, tx Tx, ns string, id influxdb.ID) (*influxdb.Document, error) {
	m, err := s.findDocumentMetaByID(ctx, tx, ns, id)
	if err != nil {
		return nil, err
	}

	d, err := s.findDocumentDataByID(ctx, tx, ns, id)
	if err != nil {
		return nil, err
	}

	return &influxdb.Document{
		ID:   id,
		Meta: *m,
		Data: d,
	}, nil
}

func (s *Service) findByID(ctx context.Context, tx Tx, bucket string, id influxdb.ID, i interface{}) error {
	b, err := tx.Bucket([]byte(bucket))
	if err != nil {
		return err
	}

	k, err := id.Encode()
	if err != nil {
		return err
	}

	v, err := b.Get(k)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(v, i); err != nil {
		return err
	}

	return nil
}

func (s *Service) findDocumentMetaByID(ctx context.Context, tx Tx, ns string, id influxdb.ID) (*influxdb.DocumentMeta, error) {
	m := &influxdb.DocumentMeta{}

	if err := s.findByID(ctx, tx, path.Join(ns, documentMetaBucket), id, m); err != nil {
		return nil, err
	}

	return m, nil
}

func (s *Service) findDocumentDataByID(ctx context.Context, tx Tx, ns string, id influxdb.ID) (interface{}, error) {
	var data interface{}
	if err := s.findByID(ctx, tx, path.Join(ns, documentDataBucket), id, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (s *DocumentStore) FindDocuments(ctx context.Context, opts ...influxdb.DocumentFindOptions) ([]*influxdb.Document, error) {
	var ds []*influxdb.Document
	err := s.service.kv.View(func(tx Tx) error {
		if len(opts) == 0 {
			// TODO(desa): might be a better way to do get all.
			if err := s.service.findDocuments(ctx, tx, s.namespace, &ds); err != nil {
				return err
			}

			return nil
		}

		idx := &DocumentIndex{
			service: s.service,
			tx:      tx,
		}

		var ids []influxdb.ID
		for _, opt := range opts {
			is, err := opt(idx)
			if err != nil {
				return err
			}

			ids = append(ids, is...)
		}

		docs, err := s.service.findDocumentsByID(ctx, tx, s.namespace, ids...)
		if err != nil {
			return err
		}

		ds = append(ds, docs...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return ds, nil
}

func (s *Service) findDocuments(ctx context.Context, tx Tx, ns string, ds *[]*influxdb.Document) error {
	metab, err := tx.Bucket([]byte(path.Join(ns, documentMetaBucket)))
	if err != nil {
		return err
	}

	cur, err := metab.Cursor()
	if err != nil {
		return err
	}

	for k, v := cur.First(); len(k) != 0; k, v = cur.Next() {
		d := &influxdb.Document{}
		if err := d.ID.Decode(k); err != nil {
			return err
		}

		if err := json.Unmarshal(v, &d.Meta); err != nil {
			return err
		}

		*ds = append(*ds, d)
	}

	for _, d := range *ds {
		data, err := s.findDocumentDataByID(ctx, tx, ns, d.ID)
		if err != nil {
			return err
		}
		d.Data = data
	}

	return nil
}

//func (s *Service) UpdateDocumentData(ctx context.Context, id influxdb.ID, data interface{}) error {
//	return s.kv.Update(func(tx Tx) error {
//		return nil
//	})
//}

func (s *DocumentStore) DeleteDocuments(ctx context.Context, opts ...influxdb.DocumentFindOptions) error {
	return s.service.kv.Update(func(tx Tx) error {
		idx := &DocumentIndex{
			service: s.service,
			tx:      tx,
			ctx:     ctx,
		}

		ids := []influxdb.ID{}
		for _, opt := range opts {
			dids, err := opt(idx)
			if err != nil {
				return err
			}

			ids = append(ids, dids...)
		}

		for _, id := range ids {
			// This removed the documents owners
			if err := WithoutOwners(id, idx); err != nil {
				return err
			}

			if err := s.service.deleteDocument(ctx, tx, s.namespace, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) removeDocumentOwner(ctx context.Context, tx Tx, ownerID, resourceID influxdb.ID) error {
	filter := influxdb.UserResourceMappingFilter{
		ResourceID: resourceID,
		UserID:     ownerID,
	}

	if err := s.deleteUserResourceMapping(ctx, tx, filter); err != nil {
		return err
	}

	return nil
}

func (s *Service) deleteDocument(ctx context.Context, tx Tx, ns string, id influxdb.ID) error {
	m, err := s.findDocumentMetaByID(ctx, tx, ns, id)
	if err != nil {
		return err
	}

	if err := s.deleteDocumentMeta(ctx, tx, ns, id); err != nil {
		return err
	}

	if err := s.deleteDocumentData(ctx, tx, ns, id); err != nil {
		return err
	}

	// TODO(desa): do this eventually
	_ = m
	//if err := s.deindexDocumentMeta(ctx, tx, id, m); err != nil {
	//	return err
	//}

	return nil
}

func (s *Service) deleteAtID(ctx context.Context, tx Tx, bucket string, id influxdb.ID) error {
	k, err := id.Encode()
	if err != nil {
		return err
	}

	b, err := tx.Bucket([]byte(bucket))
	if err != nil {
		return err
	}

	if err := b.Delete(k); err != nil {
		return err
	}

	return nil
}

func (s *Service) deleteDocumentData(ctx context.Context, tx Tx, ns string, id influxdb.ID) error {
	return s.deleteAtID(ctx, tx, path.Join(ns, documentDataBucket), id)
}

func (s *Service) deleteDocumentMeta(ctx context.Context, tx Tx, ns string, id influxdb.ID) error {
	return s.deleteAtID(ctx, tx, path.Join(ns, documentMetaBucket), id)
}

func (s *DocumentStore) UpdateDocument(ctx context.Context, d *influxdb.Document, opts ...influxdb.DocumentCreateOptions) error {
	return s.service.kv.Update(func(tx Tx) error {
		idx := &DocumentIndex{
			service: s.service,
			tx:      tx,
			ctx:     ctx,
		}
		for _, opt := range opts {
			if err := opt(d.ID, idx); err != nil {
				return err
			}
		}

		err := s.service.updateDocument(ctx, tx, s.namespace, d)
		if err != nil {
			return err
		}

		return nil
	})
}

func (s *Service) updateDocument(ctx context.Context, tx Tx, ns string, d *influxdb.Document) error {
	// TODO(desa): deindex meta

	if err := s.putDocument(ctx, tx, ns, d); err != nil {
		return err
	}

	return nil
}

func ErrInvalidDocument() *influxdb.Error {
	// TODO(desa): get the json result errors
	return &influxdb.Error{
		Code: influxdb.EInvalid,
		Msg:  "document does not fit schema",
	}
}
