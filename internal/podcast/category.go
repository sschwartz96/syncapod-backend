package podcast

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"

	"github.com/sschwartz96/syncapod-backend/internal/db"
)

type CategoryCache struct {
	// index represents id
	dbCats []db.Category
	// string represents category name
	codes map[string]int
	mutex sync.RWMutex
}

func newCategoryCache(dbCats []db.Category) *CategoryCache {
	con := CategoryCache{dbCats: make([]db.Category, 0), codes: make(map[string]int)}
	con.dbCats = append(con.dbCats, dbCats...)
	for i := range dbCats {
		con.codes[dbCats[i].Name] = dbCats[i].ID
	}
	return &con
}

// LookupIDs takes array of category ids, returns an array of Category
// with their respective sub-categories, max recursive depth of Category is 2
// parent categories MUST come before their children
func (c *CategoryCache) LookupIDs(ids []int) ([]Category, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	log.Println("LookupIDs:", ids)
	parentMap := map[int]*Category{}
	// range all ids
	for i := range ids {
		if i > len(c.dbCats) {
			return nil, errors.New("CategoryCache.LookupIDs() error: category index out of range")
		}
		log.Println("looking up cat with id:", ids[i])
		dbCat := c.dbCats[ids[i]]
		log.Printf("found cat: %s, with id: %d", dbCat.Name, dbCat.ID)
		// no parent means it is a parent, create new parent cat
		if dbCat.ParentID == 0 {
			parentMap[dbCat.ID] = &Category{ID: dbCat.ID, Name: dbCat.Name, Subcategories: []Category{}}
			continue
		}
		// check to make sure we have a valid sub category
		parent, ok := parentMap[dbCat.ParentID]
		if !ok {
			return nil, fmt.Errorf("CategoryCache.LookupIDs() error: parent map does not exist,catID: %d, parentID: %d", dbCat.ID, dbCat.ParentID)
		}
		// append to existing parent
		parent.Subcategories = append(parent.Subcategories, Category{dbCat.ID, dbCat.Name, nil})
	}
	// aggregate parents into category slice
	cats := []Category{}
	for _, c := range parentMap {
		cats = append(cats, *c)
	}
	return catSort(cats), nil
}

// TranslateCategories recursively appends category ids into the ids slice.
// Uses the codes maps held within the CategoryCache
func (c *CategoryCache) TranslateCategories(cats []Category, ids []int) []int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if cats == nil {
		return ids
	}
	for i := range cats {
		// append parent id
		ids = append(ids, c.codes[cats[i].Name])

		// recursively append children
		ids = c.TranslateCategories(cats[i].Subcategories, ids)
	}
	return ids
}

func catSort(c []Category) []Category {
	sort.Slice(c, func(i, j int) bool {
		return c[i].ID < c[j].ID
	})
	return c
}
