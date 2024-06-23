package manager

// DiskParser The information source of the disk may use a variety of methods.
// For localDisk, it only focuses on the basic information of the disk itself.
// Therefore, there is no direct binding between the disk attributes and the specific implementation.
// The parser will be responsible for docking with various tools to output fixed information
type DiskParser struct {
	// DiskIdentify
	*DiskIdentify
	*PartitionParser
	*RaidParser
	*AttributeParser
	*SmartInfoParser
}

// NewDiskParser
func NewDiskParser(
	disk *DiskIdentify,
	partitionParser *PartitionParser,
	raidParser *RaidParser,
	attrParser *AttributeParser,
	smartParser *SmartInfoParser,
) *DiskParser {
	return &DiskParser{
		DiskIdentify:    disk,
		PartitionParser: partitionParser,
		RaidParser:      raidParser,
		AttributeParser: attrParser,
		SmartInfoParser: smartParser,
	}
}

// For
func (dp *DiskParser) For(disk DiskIdentify) *DiskParser {
	dp.copyDisk(disk)
	return dp
}

// ParseDisk
func (dp *DiskParser) ParseDisk() DiskInfo {
	disk := DiskInfo{DiskIdentify: *dp.DiskIdentify}
	disk.Attribute = dp.AttributeParser.ParseDiskAttr()
	disk.Partitions = dp.PartitionParser.ParsePartitionInfo()
	disk.Smart = dp.SmartInfoParser.ParseSmartInfo()

	return disk
}

// copyDisk
func (dp *DiskParser) copyDisk(disk DiskIdentify) {
	dp.DevName = disk.DevName
	dp.DevPath = disk.DevPath
	dp.Name = disk.Name
}
