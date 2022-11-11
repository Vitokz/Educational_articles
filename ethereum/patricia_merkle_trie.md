# Patricia Merkle Trie

В bitcoin для хранения информации в блоках используется дерево Меркла. Это дерево хорошо работает для списка неизменяемых объектов для которых нужно только создавать доказательства. Так как в Ethereum данные могут меняться, необходимо было найти структуру данных которая 1) не пересчитывает все хэши после изменений 2) умеет компактно хранить данные. Эти два условия породили новую структуру для хранения информации - Patricia Merkle Trie. 
Перед разбором Patricia будут разобраны некоторые компоненты, если вы вдруг не знали о них до сего момента

## Merkle Trie

Дерево меркла - это бинарное дерево корень и ветви которого являются хэш-суммами.  Каждый родительский элемент это хэш-сумма двух дочерних хэш-сумм. Корневой хэш(**root hash**) - это вершина дерева, финальная хэш-сумма. 

![https://sun9-60.userapi.com/impf/c834303/v834303342/c8e74/L19ljO9cK9o.jpg?size=545x338&quality=96&sign=3e6c8455b6ea3ebca9488ebd49b0ae37&type=album](https://sun9-60.userapi.com/impf/c834303/v834303342/c8e74/L19ljO9cK9o.jpg?size=545x338&quality=96&sign=3e6c8455b6ea3ebca9488ebd49b0ae37&type=album)

Таким образом все элементы дерева влияют на итоговую хэш-сумму и если хотя бы один элемент изменится, то корень дерева будет совсем другим. Подобное свойство полезно,   если нам нужно проверить целостность дерева после каких-либо действий.
Представим что у нас есть есть блок данных и потребность в передаче этого блока на другой компьютер. После передачи следует убедиться что блок данных не был поврежден, как вариант можно проверять каждый бит информации чтобы убедиться в валидности данных.  Но такой метод не самый { оптимизированный }, вместо этого можно разделить блок на 8 частей и вычислить их хэш-суммы, а затем получить корневую хэш-сумму как на схеме выше. При транспортировке файла можно отправить с ним root hash и вычислить его же на машине получателя, а затем сверить и убедиться в валидности данных. Если хоть один бит изменится, то итоговый хэш будет совсем другой.

Доказательство меркла состоит из корневого хэша и ветви. Ветвь представляет собой все промежуточные хэши необходимые для получения корневого хэша

Но для простой проверки данных на целостность мы могли просто вычислить хэш-сумму всего блока данных и получить тот же результат. Но подобное целостное хэширование не позволяет проверять данные на наличие определенных частей.
Допустим нам понадобилось узнать если ли блок информации 9Dog64 в корневой хэш-сумме, мы не сможем это сделать просто закодировав sha256 блок информации. Дерево Меркла же предлагает Доказательство меркла(Merkle Proof).

![https://sun9-88.userapi.com/impf/c834303/v834303342/c8e84/vNmpFd7XcHs.jpg?size=545x338&quality=96&sign=e924d5537f0660e8880dc8e921abdcf0&type=album](https://sun9-88.userapi.com/impf/c834303/v834303342/c8e84/vNmpFd7XcHs.jpg?size=545x338&quality=96&sign=e924d5537f0660e8880dc8e921abdcf0&type=album)

Merkle Proof - это путь в дереве начиная с корня до листового узла, вместе с недостающими хэш-суммами для вычисления корневой хэш-суммы.

Например чтобы вычислить есть ли блок 9Dog64 в корневой хэш-сумме - 6с0а. Нам нужно знать все хэш-суммы по пути от 9Dog64 до 6с0а, чтобы вычислить корень еще раз и убедиться что нужный блок в дереве. 
В данном случае чтобы получит корень, нам нужно знать блок хэш соседнего блока от **9Dog64** - это хэш **1FXq18.** Теперь вычисляем хэш-сумму их хэш-сумм и получаем **781a.** Чтобы пойти дальше нам нужен **ec20**, опять вычисляем хэш-сумму и получаем **5c71.** Затем объединяем **5c71** и **8f74**, и получаем корень **6с0а**. 
Таким образом если мы знаем все хэш-суммы на пути от листа до корня, мы можем узнать если ли данный блок в корневом хэш.

### Prefix Tree

Префиксное дерево - это структура данных в виде дерева, которая позволяет реализовать ассоциативный массив, благодаря уникальности ключей. Ключи представляют из себя строки.
Ключ-строка разбивается на символы, каждый символ ветвь в дереве. У одного родителя не может быть двух дочерних ветвей с одинаковыми символами. Таким образом строится дерево, а последний символ строки будет хранить в себе значение - листовой узел.

Например для ключа HARD, мы выстроим примерно такое дерево. H→A→R→D. 
Вот еще наглядный пример

![https://habrastorage.org/r/w1560/getpro/habr/upload_files/a9b/b8c/2e7/a9bb8c2e7485693d5e4bce657e673bda.png](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a9b/b8c/2e7/a9bb8c2e7485693d5e4bce657e673bda.png)

На данной схеме выстроены слова "geek", "genius", "gene" и "genetic” в виде префиксного дерева. 
Любой узел данного дерева может содержать какую-либо информацию. На этой схеме, выделенные ветви содержат какую-либо информацию, не зависимо от того являются ли они конечным листом или нет.
Таким образом мы получили дерево для хранения информации. Данное дерево особо эффективно для хранения значений с примерно одинаковыми ключами, так как дерево особо не разветвляется.
Основные виды операций с данным деревом: Get, Set, Delete, Has

### Radix Tree

[https://www.cs.usfca.edu/~galles/visualization/RadixTree.html](https://www.cs.usfca.edu/~galles/visualization/RadixTree.html)
Radix tree(сжатое префиксное дерево) - это оптимизированная версия prefix tree, в которой каждый дочерний узел связан с единственным родительским узлом. В итоге количество дочерних узлов не превышает основание системы r, где r это 2 в степени x (в случае с алфавитом количество букв). В отличии от стандартного префиксного дерева, узлы могут состоять из целого набора символов, что делает хранение более эффективным для небольших наборов строк.

### Hex-Prefix encode

Шестнадцатиричные числа вмещают в себя 4 бита информации. А один байт вмещает 8 бит. Получается если мы будем хранить одно шестнадцатиричные число в одном байте, то мы будем использовать лишних 4 бита, что приводит к потреблению лишней памяти. Чтобы решить проблему излишнего потребления были “придуманы” полубайты(**nibbles**). Эта сущность вмещает в себя 4 бита информации, что идеально подходит под хранение 16-ых чисел.

Hex-Prefix encode - один из инструментов кодирования в Ethereum, который позволяет кодировать полубайты в байты(2 полубайта в одном байте), а также добавлять к кодируемой сущности два флага 1) **terminator** и 2) **показатель четности**.

- значение Terminator определяет является ли данный узел типом Leaf или Extension. 
 1 - leaf
 0 - extension
- значение Показателя четности определяет четное ли 16-ричная последовательность  
 1  - нечетное
 0 - четное

Данные флаги представлены в виде битов полубайта. В котором младший бит это показатель четности, а старший это терминатор. Для более лучшего понимания рассмотрите данную схему

```go
hex char    bits    |    node type partial     path length
----------------------------------------------------------
   0        0000    |       extension              even
   1        0001    |       extension              odd
   2        0010    |   terminating (leaf)         even
   3        0011    |   terminating (leaf)         odd
```

> Если число было четным до добавления префикса, то стоит добавить еще один полубайт равный 0, для сохранности четности
> 

Данный способ кодирования предназначен только для кодирования ключей для дерева, так что наличие специфичных флагов оправдано.
Таким образом требуемая память для хранения ключей уменьшается в два раза. 

Если вы хотите взглянуть на реализацию, то загляните [сюда](https://github.com/ethereum/go-ethereum/blob/master/trie/encoding.go), основная функция hexToCompact.
**Ссылки на материалы**

- [https://medium.com/coinmonks/data-structure-in-ethereum-episode-1-compact-hex-prefix-encoding-12558ae02791](https://medium.com/coinmonks/data-structure-in-ethereum-episode-1-compact-hex-prefix-encoding-12558ae02791)

### Разновидность дерева Меркла: Merkle Patricia Tree

Patricia Merkle Trie это структура данных, которая объединяет в себе Radix trie и Merkle Trie. Само дерево выглядит как Radix trie. Но Ethereum привнес в обычный radix несколько изменений. 

- Cамо дерево стало криптографически безопасным. Достигается это за счет того, что каждый узел представляет из себя **key=часть_пути** **value=hash.** Hash в value это хэш-сумма узла и одновременно ключ по которому он храниться на диске. То есть чтобы узнать что лежит в данном узле, нужно сделать запрос в хранилище на диске **с ключом равным - hash.** А так как у нас вместо реальных значений хэш-суммы узлов мы можем построить дерево Merkle и при малейшем изменении в ветвях, узнать о нарушении целостности дерева.
Таким образом мы объединили radix и merkle trie.
- Ключи кодируются с помощью HexPrefix для экономии места и включении пары флагов в ключ( терминатор и четность ).
- Были добавлены несколько видов узлов для оптимизации хранения.
    - NULL:  Просто пустое значение
    - **Leaf**: Узел - **[key, value]**, где value - это значение которое мы сохранили по этому пути
    - **Extesion**: Узел - **[key, value]**, где value - это хэш другого узла (обычно branch узел). Для получения значения узла нужно сделать запрос в хранилище с данным хэш.
    - **Branch**. Узел в котором на месте value массив из 17 элементов[key, 17[key, value]]. Наш путь состоит из hex символов, длинна алфавита hex - 16. А это значит что у родительского узла может быть 16 дочерних узлов. Вместо того чтобы строить 16 связей между родителем и дочерними элементами, можно сделать блок данных со всеми возможными дочерними элементами - то есть со всеми символами алфавита и вписывать туда значения если они есть, если же нет, то значение оставить пустым. Этим и занимается branch узел, ну а 17 ячейка предназначена для хранения значения, если путь заканчивается на branch-узле.
    Для более глубоко осознания этой информации изучите эту схему
    
    ![https://github.com/agiletechvn/go-ethereum-code-analysis/raw/master/picture/worldstatetrie.png](https://github.com/agiletechvn/go-ethereum-code-analysis/raw/master/picture/worldstatetrie.png)
    

### Разбор реализации внутри go-ethereum

Я постараюсь объяснить логику тех или иных действий, а также затрону трудно понимаемые места с которыми я столкнулся в ходе изучения. 

### node.go

Типы узлов описанные в yellow paper ethereum немного переименованы в реализации на Go. 

- FullNode - это branch узел
- ShortNode - это узел который хранит ключ-значение, но от типа значения зависит будет этот узел leaf или extension. Чтобы узел стал leaf нужно в value задать valueNode. А чтобы узел стал extension - hasnNode.

```go
type node interface {
	cache() (hashNode, bool)
	encode(w rlp.EncoderBuffer)
	fstring(string) string
}

type (
	fullNode struct {
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder)
		flags    nodeFlag
	}
	shortNode struct {
		Key   []byte
		Val   node
		flags nodeFlag
	}
	hashNode  []byte
	valueNode []byte
)
```

### encoding.go

Описанная кодировка в Hex-Prefix реализована в этом файле, есть две основные функции которые кодируют hex.

- keybytesToHex - переводит байты в hex ключ и ставит на конце 16. 16 в данном случае терминатор, который позже вырезается если узел не leaf.
- hexToCompact - кодирует hex байты в hex-prefix и добавляет префикс с флагами терминатора и четности.

```go
func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = 16
	return nibbles
}

func hexToCompact(hex []byte) []byte {
	terminator := byte(0)
	if hasTerm(hex) {
		terminator = 1
		hex = hex[:len(hex)-1]
	}
	buf := make([]byte, len(hex)/2+1)
	buf[0] = terminator << 5 // the flag byte
	if len(hex)&1 == 1 {
		buf[0] |= 1 << 4 // odd flag
		buf[0] |= hex[0] // first nibble is contained in the first byte
		hex = hex[1:]
	}
	decodeNibbles(hex, buf[1:])
	return buf
}
```

### hasher.go

Hasher - это вспомогательный инструмент который позволяет получить rootHash patriciaMerkleTree. На словах он работает довольно просто, простая итерация по дереву и замена узлов на их 32 байтные хэши. Родительский узел состоит из хэшированной суммы хэшей своих потомков и так вплоть до корня.

Вот основаная функция хэширования. Она получает корень дерева и формирует на его основе: 
rootHash - hashed 
само дерево - cached
Для branch и short узлов принцип одинаковый: сначала мы формируем хэш всех дочерних узлов(collapsed) и копируем текущий узел(cached), а далее просто сохраняем полученный хэш в спец поле, а cached кладем в root, сохранив изначальный вид дерева.

```go
// hash collapses a node down into a hash node, also returning a copy of the
// original node initialized with the computed hash to replace the original one.
func (h *hasher) hash(n node, force bool) (hashed node, cached node) {
	// Return the cached hash if it's available
	if hash, _ := n.cache(); hash != nil {
		return hash, n
	}
	// Trie not processed yet, walk the children
	switch n := n.(type) {
	case *shortNode:
		collapsed, cached := h.hashShortNodeChildren(n) // получаем collpased и cached
		hashed := h.shortnodeToHash(collapsed, force)   //   и полуаем sha256 хэш collapsed узла
		// We need to retain the possibly _not_ hashed node, in case it was too
		// small to be hashed
		if hn, ok := hashed.(hashNode); ok {
			cached.flags.hash = hn
		} else {
			cached.flags.hash = nil
		}
		return hashed, cached
	case *fullNode:
		collapsed, cached := h.hashFullNodeChildren(n)
		hashed = h.fullnodeToHash(collapsed, force)
		if hn, ok := hashed.(hashNode); ok {
			cached.flags.hash = hn
		} else {
			cached.flags.hash = nil
		}
		return hashed, cached
	default:
		// Value and hash nodes don't have children so they're left as were
		return n, n
	}
}
```

hashShortNodeChildren. Для Collapsed ключ конвертируется из Hex в Hex-prefix формат, а значение меняется на хэш дочернего элемента. Cached остается неизменным. 

```go
func (h *hasher) hashShortNodeChildren(n *shortNode) (collapsed, cached *shortNode) {
	// Hash the short node's child, caching the newly hashed subtree
	collapsed, cached = n.copy(), n.copy()

	// collapsed - та же shortNode но уже с HP ключом вместо keybytes ключом
	// cached - пока хз

	// Previously, we did copy this one. We don't seem to need to actually
	// do that, since we don't overwrite/reuse keys
	//cached.Key = common.CopyBytes(n.Key)
	collapsed.Key = hexToCompact(n.Key)
	// Unless the child is a valuenode or hashnode, hash it
	switch n.Val.(type) {
	case *fullNode, *shortNode:
		collapsed.Val, cached.Val = h.hash(n.Val, false)
	}
	return collapsed, cached
}
```

После того как мы получили collapsed узел его нужно преобразовать в sha256 хэш, для этого мы сначала пропускаем байты из key и val нашего узла через rlp. Если длинна результата кодировки достаточна(минимум 32 байта), то мы хэшируем полученные байты. А в функции hash сохраняем этот хэш в cached узле.

```go
func (h *hasher) shortnodeToHash(n *shortNode, force bool) node {
	n.encode(h.encbuf) 
	enc := h.encodedBytes()

	if len(enc) < 32 && !force {
		return n // Nodes smaller than 32 bytes are stored inside their parent
	}
	return h.hashData(enc)
}
```

### trie.go

Trie - это основная сущность реализующая дерево. 

- root - корневой узел
- owner - пользователь чьи данные хранит узел
- unhashed - количество не сохраненных изменений узлов
- reader - база данных в которой находятся сущности наших узлов
- tracer - сущность для хранения информации об изменениях в дереве, обновляется после каждого commit.

```go
// Trie is a Merkle Patricia Trie. Use New to create a trie that sits on
// top of a database. Whenever trie performs a commit operation, the generated
// nodes will be gathered and returned in a set. Once the trie is committed,
// it's not usable anymore. Callers have to re-create the trie with new root
// based on the updated trie database.
//
// Trie is not safe for concurrent use.
type Trie struct {
	root  node
	owner common.Hash

	// Keep track of the number leaves which have been inserted since the last
	// hashing operation. This number will not directly map to the number of
	// actually unhashed nodes.
	unhashed int

	// reader is the handler trie can retrieve nodes from.
	reader *trieReader

	// tracer is the tool to track the trie changes.
	// It will be reset after each commit operation.
	tracer *tracer
}
```

Рассмотрим первый кейс - добавление элемента.

В insert в зависимости от типа узла происходит запускаются разные сценарии.

> Prefix-это уже пройденный путь
Key-это оставшийся путь
n - текущий узел
> 
- short
    - Если ключ апдейта и ключ узла совпадают, то значение в текущем узле обновляется
    - Если ключи различаются, то мы переделываем short узел в branch узел с индекса различия в ключе. Создаем новый branch узел, и с места различия делаем две новые short ноды, которе добавляем в branch. В случае если они различаются с 0 индекса, то текущий узел переделывается в branch, иначе добавляется промежуточная short нода, которая сохраняет общую часть ключа.
- full
В branch узле мы просто переходим к нужному дочернему узлу
- nil
Если родительского узла нету, то просто создаем новый
- hash
Если узел хранит в себе hash узла в базе, то ищем в базе этот узел и пытаемся добавить новый узел еще раз.

```go
// tryUpdate expects an RLP-encoded value and performs the core function
// for TryUpdate and TryUpdateAccount.
func (t *Trie) tryUpdate(key, value []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(n.Key) { 
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			return true, branch, nil
		}
		// New branch node is created as a child of the original short node.
		// Track the newly inserted node in the tracer. The node identifier
		// passed is the path from the root node.
		t.tracer.onInsert(append(prefix, key[:matchlen]...))

		// Replace it with a short node leading up to the branch.
		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		// New short node is created and track it in the tracer. The node identifier
		// passed is the path from the root node. Note the valueNode won't be tracked
		// since it's always embedded in its parent.
		t.tracer.onInsert(prefix)

		return true, &shortNode{key, value, t.newFlag()}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

```

В Get происходит спуск по пути в дереве.

```go
func (t *Trie) tryGet(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.tryGet(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.tryGet(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.tryGet(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}
```

Delete

- short
    - Если у ключ узла меньше разницы, то это значит что данный узел скорее всего содержит не одно значение в ключе и узла по нужному пути просто не существует. Если ключ узла и ключ удаления идентичны, то удаляем этот узел
    - Если мы удалили дочерний элемент, а на его место пришел short узел, то вместо дочернего short узла сохраняем его value в текущий узел. Такой кейс возможен если дочерний full узел превратился в short, из-за того что у него остался только один элемент.
- full
    - Если после удаления в branch узле 2 или больше элементов, то оставляем его как есть. В противном случае нужно преобразовать branch в short ноду.

```go
// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}
		if matchlen == len(key) {
			// The matched short node is deleted entirely and track
			// it in the deletion set. The same the valueNode doesn't
			// need to be tracked at all since it's always embedded.
			t.tracer.onDelete(prefix)

			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// The child shortNode is merged into its parent, track
			// is deleted as well.
			t.tracer.onDelete(append(prefix, n.Key...))

			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			return true, &shortNode{concat(n.Key, child.Key...), child.Val, t.newFlag()}, nil
		default:
			return true, &shortNode{n.Key, child, t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn

		// Because n is a full node, it must've contained at least two children
		// before the delete operation. If the new child value is non-nil, n still
		// has at least two children after the deletion, and cannot be reduced to
		// a short node.
		if nn != nil {
			return true, n, nil
		}
		// Reduction:
		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				cnode, err := t.resolve(n.Children[pos], append(prefix, byte(pos)))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					// Replace the entire full node with the short node.
					// Mark the original short node as deleted since the
					// value is embedded into the parent now.
					t.tracer.onDelete(append(prefix, byte(pos)))

					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{k, cnode.Val, t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			return true, &shortNode{[]byte{byte(pos)}, n.Children[pos], t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
```

Commit подгатавливает NodeSet для будущего апдейта базы данных  добавление, изменение или удаление некоторых узлов. Также эта функция обновляет root узел и очищает tracer

```go
// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage
func (t *Trie) Commit(collectLeaf bool) (common.Hash, *NodeSet, error) {
	defer t.tracer.reset()

	if t.root == nil {
		return emptyRoot, nil, nil
	}
	// Derive the hash for all dirty nodes first. We hold the assumption
	// in the following procedure that all nodes are hashed.
	rootHash := t.Hash()

	// Do a quick check if we really need to commit. This can happen e.g.
	// if we load a trie for reading storage values, but don't write to it.
	if hashedNode, dirty := t.root.cache(); !dirty {
		// Replace the root node with the origin hash in order to
		// ensure all resolved nodes are dropped after the commit.
		t.root = hashedNode
		return rootHash, nil, nil
	}
	h := newCommitter(t.owner, t.tracer, collectLeaf)
	newRoot, nodes, err := h.Commit(t.root)
	if err != nil {
		return common.Hash{}, nil, err
	}
	t.root = newRoot
	return rootHash, nodes, nil
}
```

### commit.go

Commiter - это инструмент который позволяет обработать измененное дерево. Все измененные узлы помещаются в NodeSet - вспомогательную структуру для будущей операции сохранения в базу. Сам commiter прост - это будущий nodeSet и tracer - список изменений в дереве с момента прошлого commit.

```go
// leaf represents a trie leaf node
type leaf struct {
	blob   []byte      // raw blob of leaf
	parent common.Hash // the hash of parent node
}

// committer is the tool used for the trie Commit operation. The committer will
// capture all dirty nodes during the commit process and keep them cached in
// insertion order.
type committer struct {
	nodes       *NodeSet
	tracer      *tracer
	collectLeaf bool
}
```

Основной функционал это Commit. По сути происходит итерация по всему дереву во время которой ключи(key) узлов преобразовываются в hexPrefix формат, а вместо сущностей узлов в значениях(value) будут лежать хэши-ссылки на определенный узел, либо какое-то значение. В функции commit

- short: Создаем сжатую копию текущего узла и для него преобразовываем ключ, а если в value лежит branch нода, то мы преобразовываем и value, чтобы получить hashed узел
- full: Здесь тоже самое: создаем копию, преобразовываем ключ и дочерние элементы.

```go
// Commit collapses a node down into a hash node and returns it along with
// the modified nodeset.
func (c *committer) Commit(n node) (hashNode, *NodeSet, error) {
	h, err := c.commit(nil, n)
	if err != nil {
		return nil, nil, err
	}
	// Some nodes can be deleted from trie which can't be captured by committer
	// itself. Iterate all deleted nodes tracked by tracer and marked them as
	// deleted only if they are present in database previously.
	for _, path := range c.tracer.deleteList() {
		// There are a few possibilities for this scenario(the node is deleted
		// but not present in database previously), for example the node was
		// embedded in the parent and now deleted from the trie. In this case
		// it's noop from database's perspective.
		val := c.tracer.getPrev(path)
		if len(val) == 0 {
			continue
		}
		c.nodes.markDeleted(path, val)
	}
	return h.(hashNode), c.nodes, nil
}

// commit collapses a node down into a hash node and returns it.
func (c *committer) commit(path []byte, n node) (node, error) {
	// if this path is clean, use available cached data
	hash, dirty := n.cache()
	if hash != nil && !dirty {
		return hash, nil
	}
	// Commit children, then parent, and remove the dirty flag.
	switch cn := n.(type) {
	case *shortNode:
		// Commit child
		collapsed := cn.copy()

		// If the child is fullNode, recursively commit,
		// otherwise it can only be hashNode or valueNode.
		if _, ok := cn.Val.(*fullNode); ok {
			childV, err := c.commit(append(path, cn.Key...), cn.Val)
			if err != nil {
				return nil, err
			}
			collapsed.Val = childV
		}
		// The key needs to be copied, since we're adding it to the
		// modified nodeset.
		collapsed.Key = hexToCompact(cn.Key)
		hashedNode := c.store(path, collapsed)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, nil
		}
		// The short node now is embedded in its parent. Mark the node as
		// deleted if it's present in database previously. It's equivalent
		// as deletion from database's perspective.
		if prev := c.tracer.getPrev(path); len(prev) != 0 {
			c.nodes.markDeleted(path, prev)
		}
		return collapsed, nil
	case *fullNode:
		hashedKids, err := c.commitChildren(path, cn)
		if err != nil {
			return nil, err
		}
		collapsed := cn.copy()
		collapsed.Children = hashedKids

		hashedNode := c.store(path, collapsed)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn, nil
		}
		// The full node now is embedded in its parent. Mark the node as
		// deleted if it's present in database previously. It's equivalent
		// as deletion from database's perspective.
		if prev := c.tracer.getPrev(path); len(prev) != 0 {
			c.nodes.markDeleted(path, prev)
		}
		return collapsed, nil
	case hashNode:
		return cn, nil
	default:
		// nil, valuenode shouldn't be committed
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}
```

 Функция store в коде выше создает сущность memoryNode, которая в будущем должна сохраниться в базе.

```go
// store hashes the node n and adds it to the modified nodeset. If leaf collection
// is enabled, leaf nodes will be tracked in the modified nodeset as well.
func (c *committer) store(path []byte, n node) node {
	// Larger nodes are replaced by their hash and stored in the database.
	var hash, _ = n.cache()

	// This was not generated - must be a small node stored in the parent.
	// In theory, we should check if the node is leaf here (embedded node
	// usually is leaf node). But small value (less than 32bytes) is not
	// our target (leaves in account trie only).
	if hash == nil {
		return n
	}
	// We have the hash already, estimate the RLP encoding-size of the node.
	// The size is used for mem tracking, does not need to be exact
	var (
		size  = estimateSize(n)
		nhash = common.BytesToHash(hash)
		mnode = &memoryNode{
			hash: nhash,
			node: simplifyNode(n),
			size: uint16(size),
		}
	)
	// Collect the dirty node to nodeset for return.
	c.nodes.markUpdated(path, mnode, c.tracer.getPrev(path))

	// Collect the corresponding leaf node if it's required. We don't check
	// full node since it's impossible to store value in fullNode. The key
	// length of leaves should be exactly same.
	if c.collectLeaf {
		if sn, ok := n.(*shortNode); ok {
			if val, ok := sn.Val.(valueNode); ok {
				c.nodes.addLeaf(&leaf{blob: val, parent: nhash})
			}
		}
	}
	return hash
}
```

### database.go

Database - это промежуточная сущность между kv-хранилищем на диске и trie. Смысл данной сущности в создании cache памяти в процессе выполнения, кэш нужен для сокращения количества запросов на диск. Вместо постоянных запросов, payload узлов копиться, а затем по достижении лимита потребляемой памяти или с помощью специальной команды, создается батчевый запрос и узлы сохраняются в хранилище.
Сама сущность включает в себя:

```go
type Database struct {
	diskdb ethdb.KeyValueStore // Хранилище на диске, в котором хранятся узлы

	cleans  *fastcache.Cache            // Кэш-память для недавно используемых 
																			// из хранилища-диска узлов. Оптимизировано под GC

	dirties map[common.Hash]*cachedNode // Data и references relationships(связь parent-child) 
																			// измененых узлов
	oldest  common.Hash                 // Головной(старейший) узел в цепочке "грязных" узлов
	newest  common.Hash                 // Последний(новейший) узел в цепочке "грязных" узлов

	gctime  time.Duration      // Время затраченное на сборку мусора во время последнего commit
	gcnodes uint64             // Узлы собранные сборщиком во время последнего commit
	gcsize  common.StorageSize // Размер хранилища очищенного сборщиком во время последнего commit

	flushtime  time.Duration      // Время затраченное на обновление данных во время последнего commit
	flushnodes uint64             // Количество узлов добавленных с момента последнего commit
	flushsize  common.StorageSize // Размер хранилища для хранения добавленных узлов с момента последнего коммита 

	dirtiesSize  common.StorageSize // Размер хранилища кэша грязных узлов (exc. metadata)
	childrenSize common.StorageSize // Размер хранилища для отслеживания внешних дочерних узлов
	preimages    *preimageStore     // Хранилище для preimages

	lock sync.RWMutex
}
```

В данном хранилище используются свои типы для хранения узлов:

- rawNode - используется для кодирования и хранения узлов типа: **hash и value**
- rawFullNode -  используется для кодирования и хранения узлов типа: **FullNode**
- rawShortNode - используется для кодирования и хранения узлов типа: ******************ShortNode******************
- cachedNode -  используется для хранения узлов в кэше(текущем Database), но внутри этой сущности лежит node, который и сохраняется на диске(один из трех вышеописанных типов).

```go
type rawNode []byte

type rawFullNode [17]node

type rawShortNode struct {
	Key []byte
	Val node
}

type cachedNode struct {
	node node   // Cached collapsed trie node, or raw rlp data
	size uint16 // Byte size of the useful cached data

	parents  uint32                 // Number of live nodes referencing this one
	children map[common.Hash]uint16 // External children referenced by this node

	flushPrev common.Hash // Previous node in the flush-list
	flushNext common.Hash // Next node in the flush-list
}
```

Для преобразований сущностей узлов есть две функции

```go
// simplifyNode traverses the hierarchy of an expanded memory node and discards
// all the internal caches, returning a node that only contains the raw data.
func simplifyNode(n node) node {
	switch n := n.(type) {
	case *shortNode:
		// Short nodes discard the flags and cascade
		return &rawShortNode{Key: n.Key, Val: simplifyNode(n.Val)}

	case *fullNode:
		// Full nodes discard the flags and cascade
		node := rawFullNode(n.Children)
		for i := 0; i < len(node); i++ {
			if node[i] != nil {
				node[i] = simplifyNode(node[i])
			}
		}
		return node

	case valueNode, hashNode, rawNode:
		return n

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}

// expandNode traverses the node hierarchy of a collapsed storage node and converts
// all fields and keys into expanded memory form.
func expandNode(hash hashNode, n node) node {
	switch n := n.(type) {
	case *rawShortNode:
		// Short nodes need key and child expansion
		return &shortNode{
			Key: compactToHex(n.Key),
			Val: expandNode(nil, n.Val),
			flags: nodeFlag{
				hash: hash,
			},
		}

	case rawFullNode:
		// Full nodes need child expansion
		node := &fullNode{
			flags: nodeFlag{
				hash: hash,
			},
		}
		for i := 0; i < len(node.Children); i++ {
			if n[i] != nil {
				node.Children[i] = expandNode(nil, n[i])
			}
		}
		return node

	case valueNode, hashNode:
		return n

	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}
```

Теперь перейдем к основному функционалу.

**Запись в кэш**
Для записи в кэш есть функция insert. Внутри мы создаем сущность узла для хранения в кэше добавляем все дочерние элементы от заданного узла и обновляем ряд важных параметров.

```go
// insert inserts a simplified trie node into the memory database.
// All nodes inserted by this function will be reference tracked
// and in theory should only used for **trie nodes** insertion.
func (db *Database) insert(hash common.Hash, size int, node node) {
	// If the node's already cached, skip
	if _, ok := db.dirties[hash]; ok {
		return
	}
	memcacheDirtyWriteMeter.Mark(int64(size))

	// Create the cached entry for this node
	entry := &cachedNode{
		node:      node,
		size:      uint16(size),
		flushPrev: db.newest,
	}
	entry.forChilds(func(child common.Hash) {
		if c := db.dirties[child]; c != nil {
			c.parents++
		}
	})
	db.dirties[hash] = entry

	// Update the flush-list endpoints
	if db.oldest == (common.Hash{}) {
		db.oldest, db.newest = hash, hash
	} else {
		db.dirties[db.newest].flushNext, db.newest = hash, hash
	}
	db.dirtiesSize += common.StorageSize(common.HashLength + entry.size)
}
```

**Связка с внешним узлом**

 В дереве может понадобиться связать определенный узел с другим внешним узлом. Чтобы связать узел с внешним узлом нужно использовать reference

```go
// reference is the private locked version of Reference.
func (db *Database) reference(child common.Hash, parent common.Hash) {
	// If the node does not exist, it's a node pulled from disk, skip
	node, ok := db.dirties[child]
	if !ok {
		return
	}
	// If the reference already exists, only duplicate for roots
	if db.dirties[parent].children == nil {
		db.dirties[parent].children = make(map[common.Hash]uint16)
		db.childrenSize += cachedNodeChildrenSize
	} else if _, ok = db.dirties[parent].children[child]; ok && parent != (common.Hash{}) {
		return
	}
	node.parents++
	db.dirties[parent].children[child]++
	if db.dirties[parent].children[child] == 1 {
		db.childrenSize += common.HashLength + 2 // uint16 counter
	}
}
```

И dereference для отвязки. Если у дочернего внешнего узла больше нет родительских узлов(связей), то он удаляется из дерева

```go
// dereference is the private locked version of Dereference.
func (db *Database) dereference(child common.Hash, parent common.Hash) {
	// Dereference the parent-child
	node := db.dirties[parent]

	if node.children != nil && node.children[child] > 0 {
		node.children[child]--
		if node.children[child] == 0 {
			delete(node.children, child)
			db.childrenSize -= (common.HashLength + 2) // uint16 counter
		}
	}
	// If the child does not exist, it's a previously committed node.
	node, ok := db.dirties[child]
	if !ok {
		return
	}
	// If there are no more references to the child, delete it and cascade
	if node.parents > 0 {
		// This is a special cornercase where a node loaded from disk (i.e. not in the
		// memcache any more) gets reinjected as a new node (short node split into full,
		// then reverted into short), causing a cached node to have no parents. That is
		// no problem in itself, but don't make maxint parents out of it.
		node.parents--
	}
	if node.parents == 0 {
		// Remove the node from the flush-list
		switch child {
		case db.oldest:
			db.oldest = node.flushNext
			db.dirties[node.flushNext].flushPrev = common.Hash{}
		case db.newest:
			db.newest = node.flushPrev
			db.dirties[node.flushPrev].flushNext = common.Hash{}
		default:
			db.dirties[node.flushPrev].flushNext = node.flushNext
			db.dirties[node.flushNext].flushPrev = node.flushPrev
		}
		// Dereference all children and delete the node
		node.forChilds(func(hash common.Hash) {
			db.dereference(hash, child)
		})
		delete(db.dirties, child)
		db.dirtiesSize -= common.StorageSize(common.HashLength + int(node.size))
		if node.children != nil {
			db.childrenSize -= cachedNodeChildrenSize
		}
	}
}
```

**Запрос узла из хранилища.**

Для запроса информации об узле из хранилища используется node. В котором мы пытаемся найти узел в кэше, а затем в хранилище.

```go
// node retrieves a cached trie node from memory, or returns nil if none can be
// found in the memory cache.
func (db *Database) node(hash common.Hash) node {
	// Retrieve the node from the clean cache if available
	if db.cleans != nil {
		if enc := db.cleans.Get(nil, hash[:]); enc != nil {
			memcacheCleanHitMeter.Mark(1)
			memcacheCleanReadMeter.Mark(int64(len(enc)))

			// The returned value from cache is in its own copy,
			// safe to use mustDecodeNodeUnsafe for decoding.
			return mustDecodeNodeUnsafe(hash[:], enc)
		}
	}
	// Retrieve the node from the dirty cache if available
	db.lock.RLock()
	dirty := db.dirties[hash]
	db.lock.RUnlock()

	if dirty != nil {
		memcacheDirtyHitMeter.Mark(1)
		memcacheDirtyReadMeter.Mark(int64(dirty.size))
		return dirty.obj(hash)
	}
	memcacheDirtyMissMeter.Mark(1)

	// Content unavailable in memory, attempt to retrieve from disk
	enc, err := db.diskdb.Get(hash[:])
	if err != nil || enc == nil {
		return nil
	}
	if db.cleans != nil {
		db.cleans.Set(hash[:], enc)
		memcacheCleanMissMeter.Mark(1)
		memcacheCleanWriteMeter.Mark(int64(len(enc)))
	}
	// The returned value from database is in its own copy,
	// safe to use mustDecodeNodeUnsafe for decoding.
	return mustDecodeNodeUnsafe(hash[:], enc)
}
```

**Обновление данных в хранилище**

Для добавления узлов из кэша в хранилище есть дву функции Cap и Commit.
Первая вызывается если достигается лимит используемой кэшом памяти. Внутри мы  собираем все узлы в один Batch и затем разом записываем их в базу. Попутно обновляя мета-данные в структуре Database. 

```go
// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold.
//
// Note, this method is a non-synchronized mutator. It is unsafe to call this
// concurrently with other mutators.
func (db *Database) Cap(limit common.StorageSize) error {
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	nodes, storage, start := len(db.dirties), db.dirtiesSize, time.Now()
	batch := db.diskdb.NewBatch()

	// db.dirtiesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted.
	size := db.dirtiesSize + common.StorageSize((len(db.dirties)-1)*cachedNodeSize)
	size += db.childrenSize - common.StorageSize(len(db.dirties[common.Hash{}].children)*(common.HashLength+2))

	// If the preimage cache got large enough, push to disk. If it's still small
	// leave for later to deduplicate writes.
	if db.preimages != nil {
		if err := db.preimages.commit(false); err != nil {
			return err
		}
	}
	// Keep committing nodes from the flush-list until we're below allowance
	oldest := db.oldest
	for size > limit && oldest != (common.Hash{}) {
		// Fetch the oldest referenced node and push into the batch
		node := db.dirties[oldest]
		rawdb.WriteTrieNode(batch, oldest, node.rlp())

		// If we exceeded the ideal batch size, commit and reset
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				log.Error("Failed to write flush list to disk", "err", err)
				return err
			}
			batch.Reset()
		}
		// Iterate to the next flush item, or abort if the size cap was achieved. Size
		// is the total size, including the useful cached data (hash -> blob), the
		// cache item metadata, as well as external children mappings.
		size -= common.StorageSize(common.HashLength + int(node.size) + cachedNodeSize)
		if node.children != nil {
			size -= common.StorageSize(cachedNodeChildrenSize + len(node.children)*(common.HashLength+2))
		}
		oldest = node.flushNext
	}
	// Flush out any remainder data from the last batch
	if err := batch.Write(); err != nil {
		log.Error("Failed to write flush list to disk", "err", err)
		return err
	}
	// Write successful, clear out the flushed data
	db.lock.Lock()
	defer db.lock.Unlock()

	for db.oldest != oldest {
		node := db.dirties[db.oldest]
		delete(db.dirties, db.oldest)
		db.oldest = node.flushNext

		db.dirtiesSize -= common.StorageSize(common.HashLength + int(node.size))
		if node.children != nil {
			db.childrenSize -= common.StorageSize(cachedNodeChildrenSize + len(node.children)*(common.HashLength+2))
		}
	}
	if db.oldest != (common.Hash{}) {
		db.dirties[db.oldest].flushPrev = common.Hash{}
	}
	db.flushnodes += uint64(nodes - len(db.dirties))
	db.flushsize += storage - db.dirtiesSize
	db.flushtime += time.Since(start)

	memcacheFlushTimeTimer.Update(time.Since(start))
	memcacheFlushSizeMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheFlushNodesMeter.Mark(int64(nodes - len(db.dirties)))

	log.Debug("Persisted nodes from memory database", "nodes", nodes-len(db.dirties), "size", storage-db.dirtiesSize, "time", time.Since(start),
		"flushnodes", db.flushnodes, "flushsize", db.flushsize, "flushtime", db.flushtime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)

	return nil
}
```

Вторая просто сохраняет данные об узлах в хранилище, опять же одним Batch запросом, обновляя все вспомогательные метаданные.

```go
// Note, this method is a non-synchronized mutator. It is unsafe to call this
// concurrently with other mutators.
func (db *Database) Commit(node common.Hash, report bool, callback func(common.Hash)) error {
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	start := time.Now()
	batch := db.diskdb.NewBatch()

	// Move all of the accumulated preimages into a write batch
	if db.preimages != nil {
		if err := db.preimages.commit(true); err != nil {
			return err
		}
	}
	// Move the trie itself into the batch, flushing if enough data is accumulated
	nodes, storage := len(db.dirties), db.dirtiesSize

	uncacher := &cleaner{db}
	if err := db.commit(node, batch, uncacher, callback); err != nil {
		log.Error("Failed to commit trie from trie database", "err", err)
		return err
	}
	// Trie mostly committed to disk, flush any batch leftovers
	if err := batch.Write(); err != nil {
		log.Error("Failed to write trie to disk", "err", err)
		return err
	}
	// Uncache any leftovers in the last batch
	db.lock.Lock()
	defer db.lock.Unlock()
	if err := batch.Replay(uncacher); err != nil {
		return err
	}
	batch.Reset()

	// Reset the storage counters and bumped metrics
	memcacheCommitTimeTimer.Update(time.Since(start))
	memcacheCommitSizeMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheCommitNodesMeter.Mark(int64(nodes - len(db.dirties)))

	logger := log.Info
	if !report {
		logger = log.Debug
	}
	logger("Persisted trie from memory database", "nodes", nodes-len(db.dirties)+int(db.flushnodes), "size", storage-db.dirtiesSize+db.flushsize, "time", time.Since(start)+db.flushtime,
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)

	// Reset the garbage collection statistics
	db.gcnodes, db.gcsize, db.gctime = 0, 0, 0
	db.flushnodes, db.flushsize, db.flushtime = 0, 0, 0

	return nil
}

// commit is the private locked version of Commit.
func (db *Database) commit(hash common.Hash, batch ethdb.Batch, uncacher *cleaner, callback func(common.Hash)) error {
	// If the node does not exist, it's a previously committed node
	node, ok := db.dirties[hash]
	if !ok {
		return nil
	}
	var err error
	node.forChilds(func(child common.Hash) {
		if err == nil {
			err = db.commit(child, batch, uncacher, callback)
		}
	})
	if err != nil {
		return err
	}
	// If we've reached an optimal batch size, commit and start over
	rawdb.WriteTrieNode(batch, hash, node.rlp())
	if callback != nil {
		callback(hash)
	}
	if batch.ValueSize() >= ethdb.IdealBatchSize {
		if err := batch.Write(); err != nil {
			return err
		}
		db.lock.Lock()
		err := batch.Replay(uncacher)
		batch.Reset()
		db.lock.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
```

> Вполне возможно, что я где-то слукавил или что-то не рассказал. Буду благодарен если меня поправят и укажут на ошибки
> 

### Источники информации

- [https://vk.com/@blockchainlab-derevya-merkla-osnova-blokcheina-ethereum](https://vk.com/@blockchainlab-derevya-merkla-osnova-blokcheina-ethereum)
- nibble - 4 бита информации. Удобен в представлении 16-ричных цифр, так как 2^4 = 16.
- [https://ethereum.stackexchange.com/questions/68725/why-do-merckle-trees-use-nibbles](https://ethereum.stackexchange.com/questions/68725/why-do-merckle-trees-use-nibbles)
- [https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
- [https://github.com/agiletechvn/go-ethereum-code-analysis/blob/master/trie-analysis.md](https://github.com/agiletechvn/go-ethereum-code-analysis/blob/master/trie-analysis.md)
- [https://medium.com/swlh/go-the-idea-behind-sync-pool-32da5089df72](https://medium.com/swlh/go-the-idea-behind-sync-pool-32da5089df72)
- [https://easythereentropy.wordpress.com/2014/06/04/understanding-the-ethereum-trie/](https://easythereentropy.wordpress.com/2014/06/04/understanding-the-ethereum-trie/)
- [https://blog.ethereum.org/2015/11/15/merkling-in-ethereum](https://blog.ethereum.org/2015/11/15/merkling-in-ethereum)
