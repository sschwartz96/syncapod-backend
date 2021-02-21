package podcast

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/sschwartz96/syncapod-backend/internal/db"
)

type CategoryCache struct {
	// index represents id
	dbCats []db.Category
	// string represents: parent+category name
	codes map[string]int
	mutex sync.RWMutex
	// necessary to add new unknown categories
	podStore *db.PodcastStore
}

func newCategoryCache(dbCats []db.Category, podStore *db.PodcastStore) *CategoryCache {
	catCache := CategoryCache{
		dbCats:   make([]db.Category, 0),
		codes:    make(map[string]int),
		mutex:    sync.RWMutex{},
		podStore: podStore,
	}
	catCache.dbCats = append(catCache.dbCats, dbCats...)
	for i := range dbCats {
		catCache.codes[catCache.buildAncesterTree(i, "")] = dbCats[i].ID
	}
	log.Println("codes:", catCache.codes)
	return &catCache
}

// LookupIDs takes array of category ids, returns an array of Category
// with their respective sub-categories, max recursive depth of Category is 2
// parent categories MUST come before their children
func (c *CategoryCache) LookupIDs(ids []int) ([]Category, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	log.Println("LookupIDs:", ids)
	parentMap := map[int]*Category{}
	// range through all ids
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

// TranslateCategories recursively appends category ids into a slice of ids
// Uses the codes maps held within the CategoryCache
func (c *CategoryCache) TranslateCategories(cats []Category, parentID int, ids []int) ([]int, error) {
	var err error
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if cats == nil {
		return ids, nil
	}
	for i := range cats {
		cat := cats[i]
		tree := c.buildAncesterTree(cat.ID, "")
		if tree == "" {
			err = c.addNewCategory(cat, parentID)
			if err != nil {
				return nil, fmt.Errorf("TranslateCategories() error: %v", err)
			}
		}

		// append parent id
		ids = append(ids, c.codes[tree])

		// recursively append children
		ids, err = c.TranslateCategories(cat.Subcategories, cat.ID, ids)
		if err != nil {
			return nil, err
		}
	}
	return ids, nil
}

func (c *CategoryCache) addNewCategory(cat Category, parentID int) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// add id
	cat.ID = len(c.dbCats)
	dbCat := db.Category{ID: cat.ID, Name: cat.Name, ParentID: parentID}
	c.dbCats = append(c.dbCats, dbCat)
	c.codes[c.buildAncesterTree(cat.ID, cat.Name)] = cat.ID

	// insert into db
	ctx, cncFn := context.WithTimeout(context.Background(), time.Second*5)
	defer cncFn()
	return c.podStore.InsertCategory(ctx, &dbCat)
}

func catSort(c []Category) []Category {
	sort.Slice(c, func(i, j int) bool {
		return c[i].ID < c[j].ID
	})
	return c
}

func (c *CategoryCache) buildAncesterTree(i int, s string) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.dbCats[i].ParentID == 0 {
		return c.dbCats[i].Name
	}
	return c.buildAncesterTree(c.dbCats[i].ParentID, s) + c.dbCats[i].Name + s
}
